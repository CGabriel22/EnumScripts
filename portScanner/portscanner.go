package main

import (
	"fmt"
	"net"
	"strconv"
	"time"
)

func scanPort(protocol, hostname string, port int) bool {
	conn, err := net.DialTimeout(protocol, hostname+":"+strconv.Itoa(port), 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func main() {
	hostname := "scanme.nmap.org"
	for port := 1; port <= 1024; port++ {
		isOpen := scanPort("tcp", hostname, port)
		if isOpen {
			fmt.Printf("Port %d is open\n", port)
		}
	}
}
