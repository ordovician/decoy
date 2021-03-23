package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
)

var hashFuncs = map[string]hash.Hash{
	"sha256": sha256.New(),
	"md5":    md5.New(),
	"sha1":   sha1.New(),
	"sha512": sha512.New(),
}

var encoders = map[string]io.Writer{
	"base64": base64.NewEncoder(base64.StdEncoding, os.Stdout),
	"base32": base32.NewEncoder(base32.StdEncoding, os.Stdout),
	"hex":    hex.NewEncoder(os.Stdout),
}

func main() {

	var hashFn, encodeFn string
	flag.StringVar(&hashFn, "hash", "sha1", "Specify the hash function to apply to argument")
	flag.StringVar(&encodeFn, "encoding", "hex", "Encoding for hash function output")
	flag.Parse()

	h, ok := hashFuncs[strings.ToLower(hashFn)]
	if !ok {
		fmt.Fprintf(os.Stderr, "Hash function named '%s' not supported", hashFn)
		os.Exit(1)
	}
	encoder, ok := encoders[strings.ToLower(encodeFn)]
	if !ok {
		fmt.Fprintf(os.Stderr, "Encoding named '%s' not supported", encodeFn)
		os.Exit(1)
	}

	h.Write([]byte(flag.Arg(0)))
	digest := h.Sum(nil)
	_, err := encoder.Write(digest)

	if err != nil {
		fmt.Fprint(os.Stderr, "Unable to encode hashed input: ", err)
		os.Exit(1)
	}
}
