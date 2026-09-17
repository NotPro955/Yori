package main

import (
	"fmt"
	"net"
	"time"
)

func startHeartbeat(address, username string) {
	connection, err := net.Dial("tcp", address)
	if err != nil {
		fmt.Println("heartbeat unavailable:", err)
		return
	}
	defer connection.Close()
	if _, err := fmt.Fprintln(connection, username); err != nil {
		fmt.Println("heartbeat stopped:", err)
		return
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		if _, err := fmt.Fprintln(connection, "heartbeat"); err != nil {
			fmt.Println("heartbeat stopped:", err)
			return
		}
		<-ticker.C
	}
}
