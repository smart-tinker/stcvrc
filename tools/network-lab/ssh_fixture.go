package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"
)

const fixtureUser = "stcvrc-fixture"

// This disposable fixture can forward only synthetic 198.18/16 traffic to loopback HTTP.
type directTCPIP struct {
	DestAddr   string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

func main() {
	keyPath := flag.String("key-file", "", "write the ephemeral client key here")
	targetPort := flag.Int("target-port", 0, "loopback HTTP fixture port")
	readyPath := flag.String("ready-file", "", "write the SSH listener port here")
	flag.Parse()
	if err := run(*keyPath, *targetPort, *readyPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(keyPath string, targetPort int, readyPath string) error {
	if keyPath == "" || readyPath == "" || targetPort < 1 || targetPort > 65535 {
		return errors.New("key-file, ready-file, and a valid target-port are required")
	}
	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate client key: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(clientPrivate)
	if err != nil {
		return fmt.Errorf("marshal client key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write client key: %w", err)
	}
	clientSigner, err := ssh.NewSignerFromKey(clientPrivate)
	if err != nil {
		return fmt.Errorf("create client signer: %w", err)
	}

	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate host key: %w", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		return fmt.Errorf("create host signer: %w", err)
	}
	var authOnce sync.Once
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if meta.User() != fixtureUser || !bytes.Equal(key.Marshal(), clientSigner.PublicKey().Marshal()) {
				return nil, errors.New("fixture accepts only its generated public key")
			}
			authOnce.Do(func() { fmt.Fprintln(os.Stdout, "SSH_FIXTURE_AUTH_OK") })
			return &ssh.Permissions{}, nil
		},
	}
	config.AddHostKey(hostSigner)

	// Deliberately bind only to loopback; the fixture never exposes SSH to the runner network.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen on loopback: %w", err)
	}
	defer listener.Close()
	if err := os.WriteFile(readyPath, []byte(strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)), 0600); err != nil {
		return fmt.Errorf("write ready port: %w", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("accept SSH connection: %w", err)
		}
		go serve(conn, config, targetPort)
	}
}

func serve(conn net.Conn, config *ssh.ServerConfig, targetPort int) {
	defer conn.Close()
	serverConn, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer serverConn.Close()
	go ssh.DiscardRequests(requests)
	for incoming := range channels {
		switch incoming.ChannelType() {
		case "direct-tcpip":
		default:
			_ = incoming.Reject(ssh.UnknownChannelType, "fixture allows only direct-tcpip")
			continue
		}
		var req directTCPIP
		if err := ssh.Unmarshal(incoming.ExtraData(), &req); err != nil {
			_ = incoming.Reject(ssh.ConnectionFailed, "invalid direct-tcpip request")
			continue
		}
		ip := net.ParseIP(req.DestAddr).To4()
		if ip == nil || ip[0] != 198 || ip[1] != 18 || req.Port != uint32(targetPort) {
			_ = incoming.Reject(ssh.Prohibited, "fixture destination is outside the synthetic HTTP target")
			continue
		}
		target, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(targetPort)))
		if err != nil {
			_ = incoming.Reject(ssh.ConnectionFailed, "loopback HTTP target is unavailable")
			continue
		}
		channel, channelRequests, err := incoming.Accept()
		if err != nil {
			_ = target.Close()
			continue
		}
		go ssh.DiscardRequests(channelRequests)
		go relay(channel, target)
	}
}

func relay(channel ssh.Channel, target net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(target, channel)
		if tcp, ok := target.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(channel, target)
		_ = channel.CloseWrite()
		done <- struct{}{}
	}()
	<-done
	_ = channel.Close()
	_ = target.Close()
	<-done
}
