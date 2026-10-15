package openvpn

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPingRestartDiagnosticsDistinguishRejectedData(t *testing.T) {
	client, io, peer := newKeepalivePair(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for i := 0; i < 3; i++ {
		packet, err := peer.Encrypt([]byte{0x45, 0, 0, 20})
		if err != nil {
			t.Fatal(err)
		}
		if i < 2 {
			packet[len(packet)-1] ^= 1
		}
		if err := io.WritePacket(ctx, packet); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := client.ReadIPPacket(ctx); err != nil {
		t.Fatal(err)
	}
	client.lastReceiveNano.Store(int64(time.Since(start) - 10*time.Second))
	err := client.WaitPingRestart(ctx, time.Second)
	if !errors.Is(err, ErrPingRestart) {
		t.Fatalf("unexpected watchdog result: %v", err)
	}
	if strings.Contains(err.Error(), "last-data-packet=never") {
		t.Fatal("received data was reported as absent")
	}
	for _, field := range []string{"last-send=", "last-data-packet=", "inbound-data-packets=3", "data-decrypt-errors=2"} {
		if !strings.Contains(err.Error(), field) {
			t.Errorf("missing diagnostic %q in %v", field, err)
		}
	}
}

func TestPingRestartDiagnosticsShowNoDataObserved(t *testing.T) {
	client, _, _ := newKeepalivePair(t)
	client.lastReceiveNano.Store(int64(time.Since(start) - 10*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := client.WaitPingRestart(ctx, time.Second)
	if !errors.Is(err, ErrPingRestart) {
		t.Fatalf("unexpected watchdog result: %v", err)
	}
	for _, field := range []string{"last-data-packet=never", "inbound-data-packets=0", "data-decrypt-errors=0"} {
		if !strings.Contains(err.Error(), field) {
			t.Errorf("missing diagnostic %q in %v", field, err)
		}
	}
}
