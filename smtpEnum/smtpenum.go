package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
)

func main() {
	// Verify if the number of arguments is correct
	if len(os.Args) != 3 {
		fmt.Println("How to use: go run smtpenum.go IP userlist")
		os.Exit(1)
	}
	// Verify if the user list file exist
	userlistPath := os.Args[2]
	_, err := os.Stat(userlistPath)
	if os.IsNotExist(err) {
		fmt.Printf("The file '%s' not exist.\n", userlistPath)
		os.Exit(1)
	}

	// Connect to SMTP server
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:25", os.Args[1]))
	if err != nil {
		fmt.Println("Error to connect to SMTP Server: ", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Receve and print the banner
	banner := make([]byte, 1024)
	_, err = conn.Read(banner)
	if err != nil {
		fmt.Println("Error to read the server banner", err)
		os.Exit(1)
	}
	fmt.Println(string(banner) + "\n")

	// Open the user list
	file, err := os.Open(userlistPath)
	if err != nil {
		fmt.Println("Error to open the file:", err)
		os.Exit(1)
	}
	defer file.Close()

	// Search for users
	fmt.Println("searching for users...\n")
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// iterate each line
		user := scanner.Text()
		// Send the VRFY command
		_, err = fmt.Fprintf(conn, "VRFY %s\r\n", user)
		if err != nil {
			fmt.Println("Error to send VRFY command:", err)
			continue
		}

		// Capture the response
		response := make([]byte, 1024)
		_, err = conn.Read(response)
		if err != nil {
			fmt.Println("Error to read the server response about user VRFY: ", err)
			continue
		}

		// Match and print only found users, with 252 code
		if match, _ := regexp.MatchString("252", string(response)); match {
			user = strings.TrimPrefix(string(response), "252 2.0.0")
			fmt.Printf("User found: %s", strings.TrimSpace(user))
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error to read file: ", err)
	}

}
