package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base32"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

// hashPassword
func hashPassword(passwd string) string {
	digest := sha256.Sum256([]byte(passwd))
	return base32.StdEncoding.EncodeToString(digest[:])
}

func main() {
	flag.Parse()

	username := flag.Arg(0)
	passwd := flag.Arg(1)

	file, err := os.OpenFile("passwd.txt", os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		log.Fatal("Failed to open password file: ", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		fields := strings.SplitN(scanner.Text(), ":", 2)
		uname := fields[0]
		if len(fields) == 2 && username == uname {
			fmt.Fprintf(os.Stderr, "%s is already in password file", username)
			os.Exit(1)
		}
	}

	file.Seek(0, 2)
	fmt.Fprintf(file, "%s:%s\n", username, hashPassword(passwd))
}
