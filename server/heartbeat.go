package main

import (
	"fmt"
	"net"
)

func heartbeat() {
	ln, err := net.Listen("tcp", ":9500")
	if err != nil {
		panic(err)
	}

	ser := &Server{
		server_addr: ":9500",
		listener:    ln,
		clients:     make(map[net.Addr]bool),
	}

	ser.heartbeat_clients()
}

func (ser *Server) heartbeat_clients() {
	for {
		client, err := ser.listener.Accept()
		if err != nil {
			fmt.Println("accept error: ", err)
		}
		fmt.Println("[+] New clinet connected: ", client.RemoteAddr())
		ser.clients[client.RemoteAddr()] = true

		go ser.heartbeat_connection()

		for {
			status := ser.readloop(client)
			if status != "heartbeat" {
				fmt.Println("[-] Client Disconnected", client.RemoteAddr().String())
				ser.clients[client.RemoteAddr()] = false
				break
			}
		}
	}
}

func (ser *Server) heartbeat_connection() {
	for client, status := range ser.clients {
		if status {
			fmt.Println("[+] Client Connected: ", client)
		}
	}
}
