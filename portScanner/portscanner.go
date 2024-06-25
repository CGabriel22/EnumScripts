package main

import (
	"enumscripts/packages"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

func scanPort(protocol, hostname string, port int) bool {
	address := hostname + ":" + strconv.Itoa(port)
	conn, err := net.DialTimeout(protocol, address, 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func main() {
	// Verify if the number of arguments is correct
	if len(os.Args) != 3 {
		fmt.Println("How to use: sudo go run portscanner.go [TypeScan] IP/Hostname ")
		fmt.Println("TypeScan: -sT(TCP scan) or -sS(Syn scan)")
		os.Exit(1)
	}
	// for tests: "scanme.nmap.org"
	hostname := os.Args[2]
	if os.Args[1] == "-sT" {
		for port := 1; port <= 1024; port++ {
			isOpen := scanPort("tcp", hostname, port)
			if isOpen {
				fmt.Printf("Port %d is open\n", port)
			}
		}
	} else {
		packages.Synconnection()
	}
}
