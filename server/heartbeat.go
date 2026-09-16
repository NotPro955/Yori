package main

import "fmt"

func heartbeat(ser *Server) {
	for {
		fmt.Println("Heartbeating !!!!!!!!!")
		for client, cond := range ser.clients {
			fmt.Println(client, ":", cond)
		}
	}
}
