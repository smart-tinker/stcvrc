package openvpn

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/tls"
)

func TestInitialHandshakeRetriesDeferredPush(t *testing.T) {
	for _, name := range []string{"silent", "auth-pending", "continuation"} {
		t.Run(name, func(t *testing.T) {
			clientIO, serverIO := newMemoryPacketPair()
			certificate, caPEM := newTestTLSServerCertificate(t)
			client, err := newTestClient(&ClientConfig{
				Proto: ProtoUDP, CA: caPEM, Cipher: CipherAES128GCM,
				Auth: AuthSHA256, RemoteHost: "server", RemotePort: 1194,
			}, clientIO)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, err := client.Handshake(ctx)
				result <- err
			}()
			raw, err := serverIO.ReadPacket(ctx)
			if err != nil {
				t.Fatal(err)
			}
			reset, _, _, err := DecodeControlPacket(nil, raw)
			if err != nil {
				t.Fatal(err)
			}
			var serverID SessionID
			copy(serverID[:], "server01")
			control := NewControlChannel(serverIO, nil, serverID)
			control.SetRemoteSessionID(reset.LocalSession)
			control.MarkReceived(reset.MessageID)
			control.QueueAck(reset.MessageID)
			if _, err := control.Send(ctx, PControlHardResetServerV2, nil); err != nil {
				t.Fatal(err)
			}
			conn := NewControlConn(control)
			defer conn.Close()
			server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}})
			if err := server.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			_ = server.SetDeadline(time.Now().Add(3500 * time.Millisecond))
			if err := readTestClientKeyMethod(server); err != nil {
				t.Fatal(err)
			}
			if _, err := server.Write(marshalTestServerKeyMethod(t)); err != nil {
				t.Fatal(err)
			}
			readRequest := func() {
				t.Helper()
				request := make([]byte, len(PushRequest)+1)
				if _, err := io.ReadFull(server, request); err != nil {
					t.Fatalf("waiting for application PUSH_REQUEST: %v", err)
				}
				if string(request) != PushRequest+"\x00" {
					t.Fatalf("unexpected request %q", request)
				}
			}
			readRequest()
			if name == "auth-pending" {
				if _, err := server.Write([]byte("AUTH_PENDING,timeout 30\x00")); err != nil {
					t.Fatal(err)
				}
			}
			if name == "continuation" {
				if _, err := server.Write([]byte("PUSH_REPLY,push-continuation 2\x00")); err != nil {
					t.Fatal(err)
				}
				_ = server.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
				n, err := server.Read(make([]byte, 128))
				var timeout net.Error
				if n != 0 || !errors.As(err, &timeout) || !timeout.Timeout() {
					t.Fatalf("request continued after first PUSH_REPLY segment: bytes=%d error=%v", n, err)
				}
			} else {
				started := time.Now()
				readRequest()
				if time.Since(started) < 700*time.Millisecond {
					t.Fatal("PUSH_REQUEST retried without a bounded interval")
				}
			}
			if _, err := server.Write([]byte("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,cipher AES-128-GCM,push-continuation 1\x00")); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			client.control.mu.Lock()
			readDeadline, writeDeadline := client.control.readDeadline, client.control.writeDeadline
			client.control.mu.Unlock()
			if !readDeadline.IsZero() || !writeDeadline.IsZero() {
				t.Fatal("temporary push deadlines survived completed handshake")
			}
		})
	}
}
