package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stdout, "Usage of client:\n")
		flag.PrintDefaults()
	}

	var (
		port     int
		protocol string
	)

	flag.IntVar(&port, "port", 1234, "Port number for client to connect to")
	flag.StringVar(&protocol, "protocol", "tcp", "Protocol such as TCP or UDP for socket connection")
	flag.Parse()

	protocol = strings.ToLower(protocol)
	address := fmt.Sprintf("localhost:%d", port)

	if err := connect(protocol, address); err != nil {
		log.Fatal(err)
	}
}

func connect(protocol, address string) error {
	conn, err := net.Dial(protocol, address)
	if err != nil {
		return fmt.Errorf("client cannot connect to server at address %s using protocol %s", address, protocol)
	}
	defer conn.Close()

	// to hold read characters from server
	buffer := make([]byte, 512)
	input := bufio.NewScanner(os.Stdin)
	for {
		// Get data from server
		n, err := conn.Read(buffer)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return fmt.Errorf("unable to read from server: %w", err)
		}

		line := string(buffer[:n])
		fmt.Print(line)

		// Get user input
		if !(input.Scan()) {
			return fmt.Errorf("Cannot read keyboard input: %w", input.Err())
		}

		// Send input from user to server
		fmt.Fprintln(conn, input.Text())
	}

	return nil
}
