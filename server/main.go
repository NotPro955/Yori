package main

import (
	"fmt"
	"net"
)

type Server struct {
	server_addr string
	listener    net.Listener
	clients     map[net.Addr]bool
}

func NewServer(server_addr string) *Server {
	ln, err := net.Listen("tcp", server_addr)
	if err != nil {
		panic(err)
	}

	ser := &Server{
		server_addr: server_addr,
		listener:    ln,
		clients:     make(map[net.Addr]bool),
	}
	ser.accept()
	go heartbeat(ser)
	return ser
}

func (ser *Server) accept() {
	for {
		client, err := ser.listener.Accept()
		if err != nil {
			fmt.Println("accept error: ", err)
		}
		fmt.Println("[+] New clinet connected: ", client.RemoteAddr())
		ser.clients[client.RemoteAddr()] = true
	}
}

func main() {
	NewServer(":9000")
}
