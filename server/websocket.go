package main

import (
	"bufio"
	"embed"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

//go:embed web/*
var webAssets embed.FS

const (
	writeWait      = 10 * time.Second
	pongWait       = 10 * time.Second
	pingPeriod     = 30 * time.Second
	maxMessageSize = maxPacketBytes
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // The browser app is served by this public HTTP service.
	},
}

type wsClientConn struct {
	ws       *websocket.Conn
	send     chan []byte
	done     chan struct{}
	closeOnce sync.Once
}

func newWSClientConn(ws *websocket.Conn) *wsClientConn {
	return &wsClientConn{
		ws:   ws,
		send: make(chan []byte, 256),
		done: make(chan struct{}),
	}
}

func (c *wsClientConn) Read(b []byte) (n int, err error) {
	return 0, net.ErrClosed
}

func (c *wsClientConn) Write(b []byte) (n int, err error) {
	// Strip trailing newline if any, since WebSocket messages are frame-delimited
	data := b
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	cp := make([]byte, len(data))
	copy(cp, data)

	select {
	case c.send <- cp:
		return len(b), nil
	case <-c.done:
		return 0, net.ErrClosed
	default:
		return 0, net.ErrClosed
	}
}

func (c *wsClientConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		_ = c.ws.Close()
	})
	return nil
}

func (c *wsClientConn) LocalAddr() net.Addr                { return c.ws.LocalAddr() }
func (c *wsClientConn) RemoteAddr() net.Addr               { return c.ws.RemoteAddr() }
func (c *wsClientConn) SetDeadline(t time.Time) error      { return nil }
func (c *wsClientConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *wsClientConn) SetWriteDeadline(t time.Time) error { return nil }

type wsRegisterPayload struct {
	Type          string `json:"type"`
	Username      string `json:"username"`
	PreSessionPub string `json:"presession_pub"`
	Identity      string `json:"identity"`
	PublicKey     string `json:"public_key"`
}

func (ser *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	clientConn := newWSClientConn(ws)

	// Write pump goroutine: single writer to websocket
	go func() {
		ticker := time.NewTicker(pingPeriod)
		defer func() {
			ticker.Stop()
			_ = clientConn.Close()
		}()

		for {
			select {
			case msg, ok := <-clientConn.send:
				_ = ws.SetWriteDeadline(time.Now().Add(writeWait))
				if !ok {
					_ = ws.WriteMessage(websocket.CloseMessage, []byte{})
					return
				}
				if err := ws.WriteMessage(websocket.TextMessage, msg); err != nil {
					return
				}
			case <-ticker.C:
				// Once a ping is emitted, the peer has exactly pongWait to answer.
				// The initial read deadline below is longer so an otherwise idle new
				// browser is not dropped before the first 30-second ping.
				_ = ws.SetReadDeadline(time.Now().Add(pongWait))
				_ = ws.SetWriteDeadline(time.Now().Add(writeWait))
				if err := ws.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			case <-clientConn.done:
				return
			}
		}
	}()

	// Read pump
	ws.SetReadLimit(maxMessageSize)
	_ = ws.SetReadDeadline(time.Now().Add(pingPeriod + pongWait))
	ws.SetPongHandler(func(string) error {
		_ = ws.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	// First message must be registration
	_, firstMsg, err := ws.ReadMessage()
	if err != nil {
		_ = clientConn.Close()
		return
	}

	var reg wsRegisterPayload
	if err := json.Unmarshal(firstMsg, &reg); err != nil || reg.Username == "" {
		_ = write_packet(clientConn, Packet{Type: "error", Payload: "invalid registration"})
		_ = clientConn.Close()
		return
	}

	username := strings.TrimSpace(reg.Username)
	if !validUsername(username) {
		_ = write_packet(clientConn, Packet{Type: "error", Payload: "invalid username"})
		_ = clientConn.Close()
		return
	}

	ser.state_mu.Lock()
	if _, exists := ser.connections[username]; exists {
		ser.state_mu.Unlock()
		_ = write_packet(clientConn, Packet{Type: "error", Payload: "username already taken"})
		_ = clientConn.Close()
		return
	}

	prePub := reg.PreSessionPub
	if prePub == "" {
		prePub = reg.PublicKey
	}

	if ser.preSessionKeys == nil {
		ser.preSessionKeys = make(map[string]string)
	}
	if ser.peerKeys == nil {
		ser.peerKeys = make(map[string]string)
	}
	if ser.peerAddrs == nil {
		ser.peerAddrs = make(map[string]string)
	}
	if ser.identities == nil {
		ser.identities = make(map[string]string)
	}

	ser.clients[ws.RemoteAddr()] = username
	ser.connections[username] = clientConn
	ser.preSessionKeys[username] = prePub
	ser.peerKeys[username] = prePub
	ser.identities[username] = reg.Identity
	// Browser clients route through the relay and never use peer socket
	// addresses. Keeping this empty also avoids exposing a client's remote
	// address in the users response.
	ser.peerAddrs[username] = ""
	ser.state_mu.Unlock()

	ser.writeLog("[server] client connected: " + username)
	ser.broadcast_users()

	defer func() {
		ser.state_mu.Lock()
		delete(ser.clients, ws.RemoteAddr())
		delete(ser.connections, username)
		delete(ser.peerAddrs, username)
		delete(ser.peerKeys, username)
		delete(ser.identities, username)
		delete(ser.preSessionKeys, username)
		ser.state_mu.Unlock()

		ser.writeLog("[server] client disconnected: " + username)
		ser.broadcast_users()
		_ = clientConn.Close()
	}()

	// Respond with current user list immediately
	_ = write_packet(clientConn, Packet{Type: "users", Users: ser.user_list(username)})

	// Subsequent packet handling loop
	for {
		_, message, err := ws.ReadMessage()
		if err != nil {
			break
		}
		var packet Packet
		if err := json.Unmarshal(message, &packet); err != nil {
			continue
		}
		if err := validatePacket(packet); err != nil {
			continue
		}
		ser.handlePacket(clientConn, username, packet)
	}
}

// setupHTTP creates the HTTP handler serving embedded static web assets and /ws
func setupHTTP(ser *Server) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		ser.handleWebSocket(w, r)
	})

	fsys, err := fs.Sub(webAssets, "web")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(fsys))
	mux.Handle("/", fileServer)

	return mux
}

type chanListener struct {
	addr net.Addr
	ch   chan net.Conn
	done chan struct{}
}

func newChanListener(addr net.Addr) *chanListener {
	return &chanListener{
		addr: addr,
		ch:   make(chan net.Conn, 128),
		done: make(chan struct{}),
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-l.ch:
		if !ok {
			return nil, net.ErrClosed
		}
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *chanListener) Addr() net.Addr {
	return l.addr
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}
