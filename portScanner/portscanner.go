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
		tStartTime := time.Now()
		for port := 1; port <= 1024; port++ {
			isOpen := scanPort("tcp", hostname, port)
			if isOpen {
				fmt.Printf("TCP: Port %d is open\n", port)
			} else {
				fmt.Printf("TCP: Port %d is closed\n", port)
			}
		}
		tEndTime := time.Now()
		tDuration := tEndTime.Sub(tStartTime)
		fmt.Printf("Tempo de execução TCP scan: %s\n", tDuration)
	} else {
		sStartTime := time.Now()
		for key, value := range KnownPorts {
			packages.Synconnection(hostname, key, value)
		}
		sEndTime := time.Now()
		sDuration := sEndTime.Sub(sStartTime)
		fmt.Printf("Tempo de execução SYN scan: %s\n", sDuration)
	}
}
