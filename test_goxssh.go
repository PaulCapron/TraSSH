// https://godoc.org/golang.org/x/crypto/ssh#example-Dial
// sudo apt install golang && go get "golang.org/x/crypto/ssh"
package main

import (
	"log"
	"time"
	"golang.org/x/crypto/ssh"
)

func main() {
	var hostKey ssh.PublicKey

	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{ ssh.Password("sekreet") },
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout: 1 * time.Second,
	}

	log.Println("This process should hang!")

	client, err := ssh.Dial("tcp", "localhost:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		log.Fatal(err)
	}
	defer sess.Close()
}
