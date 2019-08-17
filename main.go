package main

import (
	"github.com/xialeistudio/go-socks/socks5"
	"github.com/xialeistudio/go-socks/socks5/authenticator"
	"log"
)

func main() {
	accounts := map[string]string{
		"username": "password",
	}
	authenticators := []socks5.Authenticator{
		authenticator.NewNoneAuthenticator(),
		authenticator.NewUserPasswordAuthenticator(accounts),
	}
	server := socks5.NewServer(authenticators, true)
	log.Println(server.ListenAndServe("127.0.0.1", 10000))
}
