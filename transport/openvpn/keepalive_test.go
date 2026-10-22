package openvpn

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func newKeepalivePair(t *testing.T) (*Client, *memoryPacketIO, *DataChannel) {
	t.Helper()
	return newKeepaliveCipherPair(t, CipherAES128GCM)
}

func newKeepaliveCipherPair(t *testing.T, cipher string) (*Client, *memoryPacketIO, *DataChannel) {
	t.Helper()
	clientIO, serverIO := newMemoryPacketPair()
	client, err := newTestClient(&ClientConfig{}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = serverIO.Close() })
	keys := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x11}, 16),
		RecvCipherKey: bytes.Repeat([]byte{0x11}, 16),
		SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		RecvHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
	}
	data, err := NewDataChannel(keys, cipher, AuthSHA256, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := NewDataChannel(keys, cipher, AuthSHA256, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	client.installDataChannel(data)
	return client, serverIO, peer
}

func startKeepaliveTask(t *testing.T, task func(context.Context) error) <-chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- task(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("keepalive test worker did not stop")
		}
	})
	return done
}

func readKeepalivePacket(t *testing.T, io *memoryPacketIO, peer *DataChannel) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	packet, err := io.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := peer.Decrypt(packet)
	if err != nil {
		t.Fatal(err)
	}
	return plain
}

func TestKeepaliveServerPushSendsEncryptedPing(t *testing.T) {
	client, io, peer := newKeepalivePair(t)
	push, err := ParsePushReply("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,ping 1,ping-restart 2")
	if err != nil {
		t.Fatal(err)
	}
	interval, _ := push.Keepalive(0, 0)
	startKeepaliveTask(t, func(ctx context.Context) error { return client.SendKeepalives(ctx, interval) })
	if plain := readKeepalivePacket(t, io, peer); !IsPingPacket(plain) {
		t.Fatalf("received non-ping payload: %x", plain)
	}
	if client.SinceSend() > 500*time.Millisecond {
		t.Fatal("encrypted ping did not update send activity")
	}
}

func TestKeepaliveOutboundDataSuppressesPing(t *testing.T) {
	client, io, peer := newKeepalivePair(t)
	startKeepaliveTask(t, func(ctx context.Context) error { return client.SendKeepalives(ctx, 300*time.Millisecond) })
	packet := []byte{0x45, 0, 0, 20}
	for i := 0; i < 5; i++ {
		if err := client.WriteIPPacket(context.Background(), packet); err != nil {
			t.Fatal(err)
		}
		if got := readKeepalivePacket(t, io, peer); !bytes.Equal(got, packet) {
			t.Fatal("redundant ping while outbound data was active")
		}
		time.Sleep(80 * time.Millisecond)
	}
	if plain := readKeepalivePacket(t, io, peer); !IsPingPacket(plain) {
		t.Fatal("ping did not resume after outbound data became idle")
	}
}

func TestPingRestartDoesNotResetExistingIdleDeadline(t *testing.T) {
	client, _, _ := newKeepalivePair(t)
	client.lastReceiveNano.Store(int64(time.Since(start) - 400*time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err := client.WaitPingRestart(ctx, 500*time.Millisecond)
	if !errors.Is(err, ErrPingRestart) {
		t.Fatalf("watchdog extended the existing idle deadline: %v", err)
	}
}

func TestPingRestartAuthenticatedActivityAndSilence(t *testing.T) {
	client, io, peer := newKeepalivePair(t)
	reader := startKeepaliveTask(t, func(ctx context.Context) error { _, err := client.ReadIPPacket(ctx); return err })
	watcher := startKeepaliveTask(t, func(ctx context.Context) error { return client.WaitPingRestart(ctx, 300*time.Millisecond) })
	for i := 0; i < 8; i++ {
		packet, err := peer.Encrypt(openVPNPingPacket)
		if err != nil {
			t.Fatal(err)
		}
		if err := io.WritePacket(context.Background(), packet); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(200 * time.Millisecond)
		received := func() bool {
			client.data.mu.Lock()
			defer client.data.mu.Unlock()
			return client.data.recvHighest == uint32(i+1)
		}
		for !received() && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if !received() {
			t.Fatal("authenticated ping was not consumed")
		}
		time.Sleep(60 * time.Millisecond)
		select {
		case err := <-watcher:
			t.Fatalf("restart despite authenticated inbound activity: %v", err)
		default:
		}
	}
	select {
	case err := <-watcher:
		if !errors.Is(err, ErrPingRestart) {
			t.Fatalf("unexpected watchdog result: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("silence did not trigger ping-restart")
	}
	_ = client.Close()
	select {
	case err := <-reader:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("reader did not observe teardown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reader did not stop after teardown")
	}
}

func TestPingRestartUnauthenticatedPacketsDoNotKeepAlive(t *testing.T) {
	client, io, peer := newKeepalivePair(t)
	startKeepaliveTask(t, func(ctx context.Context) error { _, err := client.ReadIPPacket(ctx); return err })
	previous := client.lastReceiveNano.Load()
	watcher := startKeepaliveTask(t, func(ctx context.Context) error { return client.WaitPingRestart(ctx, 250*time.Millisecond) })
	for i := 0; i < 6; i++ {
		packet, err := peer.Encrypt(openVPNPingPacket)
		if err != nil {
			t.Fatal(err)
		}
		packet[len(packet)-1] ^= 1
		if err := io.WritePacket(context.Background(), packet); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if client.lastReceiveNano.Load() != previous {
		t.Fatal("unauthenticated packet refreshed receive activity")
	}
	select {
	case err := <-watcher:
		if !errors.Is(err, ErrPingRestart) {
			t.Fatalf("unexpected watchdog result: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("invalid traffic prevented ping-restart")
	}
}

func TestKeepaliveCancellationAndInvalidIntervals(t *testing.T) {
	client, _, _ := newKeepalivePair(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, fn := range []func(context.Context, time.Duration) error{client.SendKeepalives, client.WaitPingRestart} {
		if err := fn(ctx, time.Second); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation ignored: %v", err)
		}
		for _, duration := range []time.Duration{0, -time.Second} {
			if err := fn(context.Background(), duration); err == nil {
				t.Fatal("invalid timer duration accepted")
			}
		}
	}
	_ = client.Close()
	for _, fn := range []func(context.Context, time.Duration) error{client.SendKeepalives, client.WaitPingRestart} {
		if err := fn(context.Background(), time.Second); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("client close ignored: %v", err)
		}
	}
}

func TestKeepaliveBlockedWriteDoesNotDelayPingRestart(t *testing.T) {
	client, _, _ := newKeepalivePair(t)
	// Fill the existing bounded memory transport, then leave its peer unread.
	for i := 0; i < 16; i++ {
		if err := client.WriteIPPacket(context.Background(), []byte{0x45, 0, 0, 20}); err != nil {
			t.Fatal(err)
		}
	}
	sender := startKeepaliveTask(t, func(ctx context.Context) error { return client.SendKeepalives(ctx, 20*time.Millisecond) })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.WaitPingRestart(ctx, 100*time.Millisecond); !errors.Is(err, ErrPingRestart) {
		t.Fatalf("blocked write delayed watchdog: %v", err)
	}
	_ = client.Close()
	select {
	case err := <-sender:
		if !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
			t.Fatalf("blocked sender did not observe teardown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked sender did not stop")
	}
}

func newKeepaliveControlPeer(t *testing.T) (*Client, *memoryPacketIO, ControlCryptor, SessionID) {
	t.Helper()
	client, io, _ := newKeepalivePair(t)
	key := bytes.Repeat([]byte{0x42}, staticKeySize)
	var err error
	client.control.crypt, err = NewTLSAuth(key, "1", AuthSHA256)
	if err != nil {
		t.Fatal(err)
	}
	peerCrypt, err := NewTLSAuth(key, "0", AuthSHA256)
	if err != nil {
		t.Fatal(err)
	}
	var serverID SessionID
	copy(serverID[:], []byte("server01"))
	client.control.SetRemoteSessionID(serverID)
	return client, io, peerCrypt, serverID
}

func TestPingRestartAcceptedControlActivityAndSilence(t *testing.T) {
	client, io, crypt, serverID := newKeepaliveControlPeer(t)
	watcher := startKeepaliveTask(t, func(ctx context.Context) error {
		return client.WaitPingRestart(ctx, 400*time.Millisecond)
	})
	for i := uint32(0); i < 8; i++ {
		packet := &ControlPacket{Opcode: PControlV1, LocalSession: serverID, MessageID: i, Payload: []byte("control")}
		raw, err := packet.Encode(crypt, i+1, 1)
		if err != nil {
			t.Fatal(err)
		}
		if err := io.WritePacket(context.Background(), raw); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err = client.control.Read(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(80 * time.Millisecond)
		select {
		case err := <-watcher:
			t.Fatalf("restart despite accepted control packets: %v", err)
		default:
		}
	}
	select {
	case err := <-watcher:
		if !errors.Is(err, ErrPingRestart) {
			t.Fatalf("unexpected watchdog result: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("control silence did not trigger restart")
	}
}

func TestPingRestartRejectedControlDoesNotRefreshActivity(t *testing.T) {
	for _, kind := range []string{"corrupt", "session", "epoch", "ack-session", "replay"} {
		t.Run(kind, func(t *testing.T) {
			client, io, crypt, serverID := newKeepaliveControlPeer(t)
			packet := &ControlPacket{Opcode: PControlV1, LocalSession: serverID, Payload: []byte("control")}
			switch kind {
			case "session":
				packet.LocalSession[0] ^= 1
			case "epoch":
				packet.KeyID = 3
			case "ack-session":
				packet.AckIDs = []uint32{1}
				packet.AckRemoteSession = serverID
			}
			raw, err := packet.Encode(crypt, 1, 1)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "corrupt" {
				raw[len(raw)-1] ^= 1
			}
			if kind == "replay" {
				if err := io.WritePacket(context.Background(), raw); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				_, err = client.control.Read(ctx)
				cancel()
				if err != nil {
					t.Fatal(err)
				}
			}
			previous := int64(time.Since(start) - time.Second)
			client.lastReceiveNano.Store(previous)
			if err := io.WritePacket(context.Background(), raw); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			_, err = client.control.Read(ctx)
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("invalid packet was accepted: %v", err)
			}
			if client.lastReceiveNano.Load() != previous {
				t.Fatal("invalid/replayed control packet refreshed keepalive")
			}
		})
	}
}

func TestKeepaliveOutboundControlSuppressesPing(t *testing.T) {
	client, io, peer := newKeepalivePair(t)
	startKeepaliveTask(t, func(ctx context.Context) error { return client.SendKeepalives(ctx, 300*time.Millisecond) })
	for i := 0; i < 6; i++ {
		if _, err := client.control.Send(context.Background(), PControlV1, []byte("control")); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		raw, err := io.ReadPacket(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if opcode, _ := parseOpcodeKeyID(raw[0]); opcode != PControlV1 {
			t.Fatal("redundant ping during active control writes")
		}
		time.Sleep(80 * time.Millisecond)
	}
	if plain := readKeepalivePacket(t, io, peer); !IsPingPacket(plain) {
		t.Fatal("ping did not resume after control writes became idle")
	}
}
