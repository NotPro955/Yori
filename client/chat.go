package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
)

func chat_session(terminal *bufio.Reader, server net.Conn, state *clientState, username, recipient string) bool {
	fmt.Println("Chatting with", recipient, "(type /back to return)")
	
	sc := &sessionCircuit{}
	_ = sc.rebuild(state, recipient)

	done := make(chan struct{})
	defer close(done)

	startCircuitRotation(state, recipient, sc, done)
	startCoverTraffic(state, recipient, sc, done)

	for {
		fmt.Print("Message: ")
		body, err := terminal.ReadString('\n')
		if err != nil {
			return false
		}
		body = strings.TrimSpace(body)
		if body == "/back" {
			clearSession(state, recipient)
			return true
		}
		if body == "/quit" {
			clearAllSessions(state)
			fmt.Fprintln(server, "quit")
			return false
		}
		if body == "" {
			continue
		}

		state.mu.Lock()
		sessionID := state.sessionIDs[recipient]
		state.sendCounts[recipient]++
		counter := state.sendCounts[recipient]
		currentKey, ok := state.outgoing[recipient]
		var key []byte
		if ok {
			key = append([]byte(nil), currentKey...)
		}
		state.mu.Unlock()

		if !ok {
			fmt.Println("session was closed, type /back and start a new session")
			continue
		}

		messageID, err := randomID()
		if err != nil {
			log.Println("message id error:", err)
			continue
		}
		envelope, err := json.Marshal(chatEnvelope{Version: protocolVersion, MessageID: messageID, SessionID: sessionID, Counter: counter, Sender: username, Body: body})
		if err != nil {
			log.Println("message encoding error:", err)
			continue
		}
		paddedEnv := pad256(envelope)
		ciphertext, err := encryptBytesAAD(key, paddedEnv, []byte("yori/message/v1|"+sessionID))
		if err != nil {
			log.Println("encrypt error:", err)
			continue
		}
		if err := sc.sendOnCircuit(state, recipient, Packet{Type: "send", To: recipient, Payload: ciphertext}); err != nil {
			log.Println("circuit send error:", err)
			continue
		}
		fmt.Println("sent through onion route")
	}
}
