package openvpn

import (
	"testing"
	"time"
)

func TestPushReplyRejectsInvalidKeepalive(t *testing.T) {
	for _, option := range []string{
		"ping", "ping -1", "ping invalid", "ping 1 2",
		"ping-restart", "ping-restart -1", "ping-restart invalid",
		"ping 9223372037", "ping-restart 9223372037",
	} {
		t.Run(option, func(t *testing.T) {
			if _, err := ParsePushReply("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0," + option); err == nil {
				t.Fatal("invalid keepalive was silently accepted")
			}
		})
	}
}

func TestPushReplyKeepalive(t *testing.T) {
	for _, tc := range []struct {
		name, options string
		localInterval time.Duration
		localRestart  time.Duration
		wantInterval  time.Duration
		wantRestart   time.Duration
	}{
		{"server-only", ",ping 10,ping-restart 60", 0, 0, 10 * time.Second, 60 * time.Second},
		{"local-only", "", 5 * time.Second, 30 * time.Second, 5 * time.Second, 30 * time.Second},
		{"server-overrides-local", ",ping 10,ping-restart 60", 5 * time.Second, 30 * time.Second, 10 * time.Second, 60 * time.Second},
		{"disabled", ",ping 0,ping-restart 0", 5 * time.Second, 30 * time.Second, 0, 0},
		{"partial", ",ping 10", 5 * time.Second, 30 * time.Second, 10 * time.Second, 30 * time.Second},
		{"omitted", "", 0, 0, 0, 0},
		{"repeated-last-wins", ",ping 10,ping 0,ping-restart 60,ping-restart 30", 0, 0, 0, 30 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			push, err := ParsePushReply("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0" + tc.options)
			if err != nil {
				t.Fatal(err)
			}
			interval, restart := push.Keepalive(tc.localInterval, tc.localRestart)
			if interval != tc.wantInterval || restart != tc.wantRestart {
				t.Fatalf("keepalive = (%s, %s), want (%s, %s)", interval, restart, tc.wantInterval, tc.wantRestart)
			}
		})
	}
}

func TestPushReplyKeepaliveContinuationAndTokenRefresh(t *testing.T) {
	push, rest, ok := takePushReply([]byte("PUSH_REPLY,ping 10,push-continuation 2\x00PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,ping-restart 60,push-continuation 1\x00"))
	if !ok || len(rest) != 0 || push == nil {
		t.Fatal("keepalive continuation not assembled")
	}
	refresh, err := parsePushReplyInner("PUSH_REPLY,auth-token test-token")
	if err != nil {
		t.Fatal(err)
	}
	merged := mergePushReply(push, refresh)
	interval, restart := merged.Keepalive(0, 0)
	if interval != 10*time.Second || restart != 60*time.Second {
		t.Fatalf("token refresh lost timers: %s, %s", interval, restart)
	}
	disabled, err := parsePushReplyInner("PUSH_REPLY,ping 0,ping-restart 0")
	if err != nil {
		t.Fatal(err)
	}
	interval, restart = mergePushReply(merged, disabled).Keepalive(time.Second, time.Second)
	if interval != 0 || restart != 0 {
		t.Fatalf("explicit disable lost in merge: %s, %s", interval, restart)
	}
}
