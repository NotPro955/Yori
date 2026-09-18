package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
)

func chat_session(terminal *bufio.Reader, server net.Conn, state *clientState, username, recipient string, key []byte) bool {
	fmt.Println("Chatting with", recipient, "(type /back to return)")
	for {
		fmt.Print("Message: ")
		body, err := terminal.ReadString('\n')
		if err != nil {
			return false
		}
		body = strings.TrimSpace(body)
		if body == "/back" {
			return true
		}
		if body == "/quit" {
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
		state.mu.Unlock()
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
		ciphertext, err := encryptBytesAAD(key, envelope, []byte("yori/message/v1|"+sessionID))
		if err != nil {
			log.Println("encrypt error:", err)
			continue
		}
		if err := directSendToUser(state, recipient, Packet{Type: "send", To: recipient, Payload: ciphertext}); err != nil {
			log.Println("direct send error:", err)
			return false
		}
		fmt.Println("sent through onion route")
	}
}
