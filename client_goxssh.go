// https://godoc.org/golang.org/x/crypto/ssh#example-Dial
// sudo apt install golang && go get "golang.org/x/crypto/ssh"
package main

import (
	"golang.org/x/crypto/ssh"
	"log"
	"os"
	"time"
)

func main() {
	var addr string
	switch len(os.Args) {
	case 1:
		addr = "localhost:22"
	case 2:
		addr = "localhost:" + os.Args[1]
	default:
		log.Println("Usage: go run client_goxssh.go [port=22]\n")
		os.Exit(64)
	}

	var hostKey ssh.PublicKey
	config := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password("sekreet")},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         5 * time.Second,
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	log.Println("Attempting SSH connection to", addr, "…")

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		log.Fatal(err)
	}
	client.Close()
}
