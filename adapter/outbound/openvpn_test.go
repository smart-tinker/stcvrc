package outbound

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

type openVPNTestTimeoutError struct{}

func (openVPNTestTimeoutError) Error() string   { return "test timeout" }
func (openVPNTestTimeoutError) Timeout() bool   { return true }
func (openVPNTestTimeoutError) Temporary() bool { return false }

func TestOpenVPNDataDialTimeoutThreshold(t *testing.T) {
	o := &OpenVPN{}
	now := time.Unix(1000, 0)

	if o.observeDataDialTimeout(now, "192.0.2.1:443") {
		t.Fatal("first timeout should not trigger reconnect")
	}
	if o.observeDataDialTimeout(now.Add(time.Second), "192.0.2.1:443") {
		t.Fatal("repeated timeout to the same target should not trigger reconnect")
	}
	if !o.observeDataDialTimeout(now.Add(2*time.Second), "192.0.2.2:443") {
		t.Fatal("timeouts to distinct targets inside window should trigger reconnect")
	}
	if o.observeDataDialTimeout(now.Add(3*time.Second), "192.0.2.3:443") {
		t.Fatal("reconnect should respect cooldown")
	}
	if o.observeDataDialTimeout(now.Add(openVPNDataDialReconnectCooldown+time.Second), "192.0.2.3:443") {
		t.Fatal("first timeout after cooldown should not trigger reconnect")
	}
	if !o.observeDataDialTimeout(now.Add(openVPNDataDialReconnectCooldown+2*time.Second), "192.0.2.4:443") {
		t.Fatal("continued timeouts after cooldown should trigger another reconnect")
	}
	if o.observeDataDialTimeout(now.Add(openVPNDataDialReconnectCooldown+3*time.Second), "192.0.2.5:443") {
		t.Fatal("second reconnect should respect cooldown")
	}
}

func TestOpenVPNDataDialTimeoutWindowAndReset(t *testing.T) {
	o := &OpenVPN{}
	now := time.Unix(1000, 0)

	if o.observeDataDialTimeout(now, "192.0.2.1:443") {
		t.Fatal("first timeout should not trigger reconnect")
	}
	if o.observeDataDialTimeout(now.Add(openVPNDataDialTimeoutWindow+time.Second), "192.0.2.2:443") {
		t.Fatal("timeout outside the window should start a new window")
	}
	if !o.observeDataDialTimeout(now.Add(openVPNDataDialTimeoutWindow+2*time.Second), "192.0.2.3:443") {
		t.Fatal("second timeout in the new window should trigger reconnect")
	}

	o.resetDataDialTimeouts()
	if o.observeDataDialTimeout(now.Add(2*openVPNDataDialTimeoutWindow), "192.0.2.4:443") {
		t.Fatal("reset should clear the timeout counter")
	}
}

func TestOpenVPNDataDialTimeoutIgnoresChronicDeadTarget(t *testing.T) {
	o := &OpenVPN{}
	now := time.Unix(1000, 0)
	chronicTarget := "192.0.2.1:22"

	if o.observeDataDialTimeout(now, chronicTarget) {
		t.Fatal("first timeout should not trigger reconnect")
	}
	if o.observeDataDialTimeout(now.Add(20*time.Second), chronicTarget) {
		t.Fatal("second timeout to one target should not trigger reconnect")
	}
	if o.observeDataDialTimeout(now.Add(40*time.Second), chronicTarget) {
		t.Fatal("chronic target should be suppressed, not trigger reconnect")
	}
	if o.observeDataDialTimeout(now.Add(50*time.Second), "192.0.2.2:3389") {
		t.Fatal("one non-chronic target plus one chronic target should not trigger reconnect")
	}
	if !o.observeDataDialTimeout(now.Add(51*time.Second), "192.0.2.3:445") {
		t.Fatal("two non-chronic targets should still trigger reconnect")
	}
}

func TestOpenVPNDataDialSuccessClearsChronicTarget(t *testing.T) {
	o := &OpenVPN{}
	now := time.Unix(1000, 0)
	target := "192.0.2.1:22"

	o.observeDataDialTimeout(now, target)
	o.observeDataDialTimeout(now.Add(20*time.Second), target)
	o.observeDataDialTimeout(now.Add(40*time.Second), target)
	o.observeDataDialSuccess(target)

	if o.observeDataDialTimeout(now.Add(50*time.Second), target) {
		t.Fatal("successful dial should clear chronic-target suppression")
	}
	if !o.observeDataDialTimeout(now.Add(51*time.Second), "192.0.2.2:3389") {
		t.Fatal("target should contribute normally after a successful dial")
	}
}

func TestIsOpenVPNDataDialTimeout(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "context deadline", err: context.DeadlineExceeded, want: true},
		{name: "os deadline", err: os.ErrDeadlineExceeded, want: true},
		{name: "wrapped net timeout", err: errors.Join(errors.New("dial tcp"), openVPNTestTimeoutError{}), want: true},
		{name: "ordinary refused", err: errors.New("connect: connection refused"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isOpenVPNDataDialTimeout(tt.err); got != tt.want {
				t.Fatalf("isOpenVPNDataDialTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}
