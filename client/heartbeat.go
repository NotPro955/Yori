package main

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

func startHeartbeat(address, username string) {
	connection, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		fmt.Println("heartbeat unavailable:", err)
		return
	}
	defer connection.Close()
	registrationID, err := randomID()
	if err != nil {
		fmt.Println("heartbeat stopped:", err)
		return
	}
	registration, err := json.Marshal(Packet{Version: protocolVersion, ID: registrationID, Type: "heartbeat", Payload: username})
	if err != nil {
		fmt.Println("heartbeat stopped:", err)
		return
	}
	if _, err := connection.Write(append(registration, '\n')); err != nil {
		fmt.Println("heartbeat stopped:", err)
		return
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		heartbeatID, err := randomID()
		if err != nil {
			fmt.Println("heartbeat stopped:", err)
			return
		}
		heartbeat, err := json.Marshal(Packet{Version: protocolVersion, ID: heartbeatID, Type: "heartbeat"})
		if err != nil {
			fmt.Println("heartbeat stopped:", err)
			return
		}
		_ = connection.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := connection.Write(append(heartbeat, '\n')); err != nil {
			fmt.Println("heartbeat stopped:", err)
			return
		}
		<-ticker.C
	}
}
