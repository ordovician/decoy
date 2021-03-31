package main

import (
	"bufio"
	"embed"
	"fmt"
	"os"
	"strings"
)

//go:embed data
var storage embed.FS

// runShell creates a command line where you can issue
// simple commands such as ls and cat in a pretend Unix shell.
func runShell() {

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("> ")

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		cmd := Lookup(fields[0])
		if cmd == nil {
			fmt.Println("Unknown command:", fields[0])
		} else {
			cmd.Run(os.Stdout, fields[1:])
		}
		fmt.Print("> ")
	}
}
