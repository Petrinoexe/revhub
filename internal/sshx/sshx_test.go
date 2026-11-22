package sshx

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestRunConcurrentOutput(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		go ssh.DiscardRequests(reqs)
		ch := <-chans
		channel, requests, err := ch.Accept()
		if err != nil {
			done <- err
			return
		}
		req := <-requests
		if req.Type != "exec" {
			done <- fmt.Errorf("unexpected request %s", req.Type)
			return
		}
		req.Reply(true, nil)
		complete := make(chan bool, 2)
		go func() {
			for i := 0; i < 200; i++ {
				fmt.Fprint(channel, strings.Repeat("A", 1024))
			}
			complete <- true
		}()
		go func() {
			for i := 0; i < 200; i++ {
				fmt.Fprint(channel.Stderr(), strings.Repeat("B", 1024))
			}
			complete <- true
		}()
		<-complete
		<-complete
		channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		channel.Close()
		done <- nil
	}()
	client, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{User: "test", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	c := &Client{c: client}
	out, err := c.Run("test")
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, "A") != 204800 || strings.Count(out, "B") != 204800 {
		t.Fatalf("lost output: A=%d B=%d", strings.Count(out, "A"), strings.Count(out, "B"))
	}
}
