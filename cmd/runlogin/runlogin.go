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
	cwd, _ := os.Getwd()
	debug.Println("Opened passwd.txt file in ", cwd)

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		fields := strings.SplitN(scanner.Text(), ":", 2)
		debug.Printf("Number fields read %d", len(fields))
		if len(fields) >= 2 {
			debug.Printf("Read username %s and hashed password %s from password fields\n", fields[0], fields[1])
		}

		uname := fields[0]
		debug.Printf("Comparing %s == %s", user, uname)
		if len(fields) == 2 && user == uname {
			debug.Println("comparing ", fields[1], " with ", hashPassword(passwd))
			return fields[1] == hashPassword(passwd), nil
		}
	}

	return false, nil
}

func main() {
	fmt.Print("Login: ")
	input := bufio.NewReader(os.Stdin)
	user, err := input.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read login name: %v", err)
	}

	user = strings.TrimSuffix(user, "\n")
	debug.Println("Read user: ", user)

	fmt.Print("Password: ")
	passwd, err := input.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read password: %v", err)
	}
	passwd = strings.TrimSuffix(passwd, "\n")
	debug.Println("Read password: ", passwd)

	if ok, err := checkLogin(user, passwd); ok {
		fmt.Println("You are logged in!")
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "Could not log in becase: %v", err)
	} else {
		fmt.Print("Username does not exist or password was wrong")
	}
}
