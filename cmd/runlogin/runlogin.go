package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"log"
	"os"
	"strings"
)

var debug *log.Logger = log.New(os.Stdout, "", 0)

// hashPassword
func hashPassword(passwd string) string {
	digest := sha256.Sum256([]byte(passwd))
	return base32.StdEncoding.EncodeToString(digest[:])
}

func checkLogin(user, passwd string) (bool, error) {
	file, err := os.Open("passwd.txt")
	if err != nil {
		return false, fmt.Errorf("Error when opening password file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		fields := strings.SplitN(scanner.Text(), ":", 2)

		uname := fields[0]
		if len(fields) == 2 && user == uname {
			return fields[1] == hashPassword(passwd), nil
		}
	}

	return false, nil
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Login: ")
	if !scanner.Scan() {
		fmt.Fprintln(os.Stderr, "Unable to get login name:", scanner.Err())
		os.Exit(1)
	}

	user := scanner.Text()

	fmt.Print("Password: ")
	if !scanner.Scan() {
		fmt.Fprintln(os.Stderr, "Unable to get password:", scanner.Err())
		os.Exit(1)
	}

	passwd := scanner.Text()

	if ok, err := checkLogin(user, passwd); ok {
		fmt.Println("You are logged in!")
	} else if err != nil {
		fmt.Fprintln(os.Stderr, "Could not log in becase:", err)
	} else {
		fmt.Print("Username does not exist or password was wrong")
	}
}
