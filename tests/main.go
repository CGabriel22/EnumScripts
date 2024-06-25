package main

import (
	"enumscripts/tests/gopackettest"
	"enumscripts/tests/scripttest"
	"fmt"
)

func main() {

	fmt.Println("My script test:")
	scripttest.Run()

	fmt.Println("\nGopacket script test:")
	gopackettest.Run("45.33.32.156")
}
