package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

func heartbeat(ser *Server) {
	ln, err := net.Listen("tcp", ":9500")
	if err != nil {
		panic(err)
	}
	ser.heartbeat_listener(ln)
}

func (ser *Server) heartbeat_listener(ln net.Listener) {
	for {
		client, err := ln.Accept()

		if err != nil {
			fmt.Println("accept error: ", err)
			continue
		}
		reader := bufio.NewScanner(client)
		if !reader.Scan() {
			client.Close()
			continue
		}
		username := strings.TrimSpace(reader.Text())
		ser.state_mu.Lock()
		ser.heartbeats[client.RemoteAddr()] = username
		ser.state_mu.Unlock()

		go heartbeat_connection(ser, client, reader)
	}

}

func heartbeat_connection(ser *Server, client net.Conn, reader *bufio.Scanner) {
	defer client.Close()
	defer func() {
		ser.state_mu.Lock()
		delete(ser.heartbeats, client.RemoteAddr())
		ser.state_mu.Unlock()
	}()
	for {
		if !reader.Scan() || strings.TrimSpace(reader.Text()) != "heartbeat" {
			break
		}
	}
	if reader.Err() != nil {
		return
	}
}
