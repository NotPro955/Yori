package main

import (
	"fmt"
	"net"
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
		}
		fmt.Println("[+] New Heartbeat connected: ", client.RemoteAddr())
		client_status := ser.clients[client.RemoteAddr()]
		client_status = true

		go heartbeat_connection(client, client_status)
	}

}

func heartbeat_connection(client net.Conn, client_status bool) {
	for {
		beat := readloop(client)
		if beat != "heartbeat" {
			fmt.Println("[-] No heartbeat: ", client.RemoteAddr())
			client_status = false
			break
		}
	}
}
