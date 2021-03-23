// Generates an encryption key
package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	// Define the flags that are valid for this application
	var keyLen int         // length of encryption key
	var encodingStr string // how we encode the generated key

	flag.IntVar(&keyLen, "keylen", 16, "Length of encryption key")
	flag.StringVar(&encodingStr, "encoding", "hex", "Encoding to use for key. Could be hex, base32, base64 or pem")
	flag.Parse()

	// Generate key
	key := make([]byte, keyLen)
	_, err := rand.Read(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not generate encryption key:", err)
		os.Exit(1)
	}

	// Figure out where to store key or to output to console
	var out io.Writer = os.Stdout
	if flag.NArg() > 0 {
		file, err := os.Create(flag.Arg(0))
		if err != nil {
			fmt.Fprintln(os.Stderr, "Could not create file store key:", err)
			os.Exit(1)
		}
		defer file.Close()
		out = file
	}

	// Store key using configured encoding
	err = Encode(key, strings.ToLower(encodingStr), out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

// Encode key using encoding given by encodingStr, writing result out to out.
func Encode(key []byte, encodingStr string, out io.Writer) error {
	if encodingStr == "pem" {
		var pemBlock = pem.Block{
			Type:  "AES PRIVATE KEY",
			Bytes: key,
		}
		pem.Encode(out, &pemBlock)
		return nil
	}

	switch encodingStr {
	case "base64":
		encoder := base64.NewEncoder(base64.StdEncoding, out)
		encoder.Write(key)
		encoder.Close()
	case "base32":
		encoder := base32.NewEncoder(base32.StdEncoding, out)
		encoder.Write(key)
		encoder.Close()
	case "hex":
		encoder := hex.NewEncoder(out)
		encoder.Write(key)
	default:
		return fmt.Errorf("We don't support %s encoding", encodingStr)
	}

	return nil
}
