package openvpn

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeControlStream struct {
	readCh  chan []byte
	writeCh chan []byte

	mu           sync.Mutex
	readDeadline time.Time
	closed       bool
}

func newFakeControlStream() *fakeControlStream {
	return &fakeControlStream{
		readCh:  make(chan []byte, 8),
		writeCh: make(chan []byte, 8),
	}
}

func (f *fakeControlStream) Read(b []byte) (int, error) {
	f.mu.Lock()
	deadline := f.readDeadline
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if deadline.IsZero() {
		msg, ok := <-f.readCh
		if !ok {
			return 0, net.ErrClosed
		}
		return copy(b, msg), nil
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case msg, ok := <-f.readCh:
		if !ok {
			return 0, net.ErrClosed
		}
		return copy(b, msg), nil
	case <-timer.C:
		return 0, timeoutError{}
	}
}

func (f *fakeControlStream) Write(b []byte) (int, error) {
	f.mu.Lock()
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	f.writeCh <- cloneBytes(b)
	return len(b), nil
}

func (f *fakeControlStream) SetReadDeadline(t time.Time) error {
	f.mu.Lock()
	f.readDeadline = t
	f.mu.Unlock()
	return nil
}

func (f *fakeControlStream) SetWriteDeadline(time.Time) error {
	return nil
}

func (f *fakeControlStream) Close() {
	f.mu.Lock()
	if !f.closed {
		f.closed = true
		close(f.readCh)
	}
	f.mu.Unlock()
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestNewClientInitializesWriteSemaphore(t *testing.T) {
	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{
		RemoteHost: "127.0.0.1",
		RemotePort: 1194,
	}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if client.writeSem == nil {
		t.Fatal("write semaphore is nil")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.writeSem.Acquire(ctx, 1); err != nil {
		t.Fatalf("write semaphore Acquire blocked or failed: %v", err)
	}
	client.writeSem.Release(1)
}

type oneShotReadErrorStream struct {
	*fakeControlStream

	mu  sync.Mutex
	err error
}

func newOneShotReadErrorStream(err error) *oneShotReadErrorStream {
	return &oneShotReadErrorStream{
		fakeControlStream: newFakeControlStream(),
		err:               err,
	}
}

func (s *oneShotReadErrorStream) Read(b []byte) (int, error) {
	s.mu.Lock()
	err := s.err
	s.err = nil
	s.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return s.fakeControlStream.Read(b)
}

func TestClientInstallDataChannelKeepsPreviousSendKeyDuringActivation(t *testing.T) {
	client := &Client{
		config: &ClientConfig{
			Cipher:           CipherAES128GCM,
			Auth:             AuthSHA256,
			TransitionWindow: 20 * time.Millisecond,
		},
		activity: newRemoteActivity(),
	}
	keys1 := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x11}, 16),
		SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x33}, 16),
		RecvHMACKey:   bytes.Repeat([]byte{0x44}, maxHMACKeyLength),
	}
	keys2 := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x55}, 16),
		SendHMACKey:   bytes.Repeat([]byte{0x66}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x77}, 16),
		RecvHMACKey:   bytes.Repeat([]byte{0x88}, maxHMACKeyLength),
	}
	if err := client.installDataChannel(keys1, &PushReply{PeerID: 7}, false, CipherAES128GCM, AuthSHA256); err != nil {
		t.Fatal(err)
	}
	initial := client.data
	if initial == nil {
		t.Fatal("expected initial data channel")
	}
	now := time.Unix(100, 0)
	initial.clock = func() time.Time { return now }
	if err := client.installDataChannel(keys2, &PushReply{PeerID: 7}, true, CipherAES128GCM, AuthSHA256); err != nil {
		t.Fatal(err)
	}
	if client.data != initial {
		t.Fatal("expected in-place rekey to keep the data channel object")
	}
	encrypted, err := client.data.Encrypt([]byte{0x45, 0, 0, 20, 1, 2, 3, 4, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, keyID := parseOpcodeKeyID(encrypted[0]); keyID != 0 {
		t.Fatalf("expected previous key id 0 during activation delay, got %d", keyID)
	}
	now = now.Add(client.dataKeyActivationDelay())
	encrypted, err = client.data.Encrypt([]byte{0x45, 0, 0, 20, 1, 2, 3, 5, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, keyID := parseOpcodeKeyID(encrypted[0]); keyID != 1 {
		t.Fatalf("expected encrypted packets to use rekeyed key id 1, got %d", keyID)
	}
}

func TestTLSVersionUsesConfiguredMinVersion(t *testing.T) {
	minVersion, err := tlsVersion(TLSVersion10)
	if err != nil {
		t.Fatal(err)
	}
	if minVersion != tls.VersionTLS10 {
		t.Fatalf("unexpected min TLS version: %x", minVersion)
	}

	maxVersion, err := tlsVersion(TLSVersion13)
	if err != nil {
		t.Fatal(err)
	}
	if maxVersion != tls.VersionTLS13 {
		t.Fatalf("unexpected max TLS version: %x", maxVersion)
	}
}

func TestClientInstallDataChannelRetiresPreviousReceiveKeyAfterOverlap(t *testing.T) {
	clientKeys1 := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x11}, 16),
		SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x33}, 16),
		RecvHMACKey:   bytes.Repeat([]byte{0x44}, maxHMACKeyLength),
	}
	serverKeys1 := &KeyMaterial{
		SendCipherKey: clientKeys1.RecvCipherKey,
		SendHMACKey:   clientKeys1.RecvHMACKey,
		RecvCipherKey: clientKeys1.SendCipherKey,
		RecvHMACKey:   clientKeys1.SendHMACKey,
	}
	clientKeys2 := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x55}, 16),
		SendHMACKey:   bytes.Repeat([]byte{0x66}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x77}, 16),
		RecvHMACKey:   bytes.Repeat([]byte{0x88}, maxHMACKeyLength),
	}
	serverKeys2 := &KeyMaterial{
		SendCipherKey: clientKeys2.RecvCipherKey,
		SendHMACKey:   clientKeys2.RecvHMACKey,
		RecvCipherKey: clientKeys2.SendCipherKey,
		RecvHMACKey:   clientKeys2.SendHMACKey,
	}
	client := &Client{
		config: &ClientConfig{
			Cipher:           CipherAES128GCM,
			Auth:             AuthSHA256,
			TransitionWindow: 20 * time.Millisecond,
		},
		activity: newRemoteActivity(),
	}
	if err := client.installDataChannel(clientKeys1, &PushReply{PeerID: 7}, false, CipherAES128GCM, AuthSHA256); err != nil {
		t.Fatal(err)
	}
	server, err := NewDataChannel(serverKeys1, CipherAES128GCM, AuthSHA256, 7, "")
	if err != nil {
		t.Fatal(err)
	}
	oldPacketDuringOverlap := []byte{0x45, 0, 0, 20, 1, 2, 3, 4, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1}
	oldEncryptedDuringOverlap, err := server.Encrypt(oldPacketDuringOverlap)
	if err != nil {
		t.Fatal(err)
	}
	oldPacketAfterOverlap := []byte{0x45, 0, 0, 20, 1, 2, 3, 6, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1}
	oldEncryptedAfterOverlap, err := server.Encrypt(oldPacketAfterOverlap)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.installDataChannel(clientKeys2, &PushReply{PeerID: 7}, true, CipherAES128GCM, AuthSHA256); err != nil {
		t.Fatal(err)
	}
	if _, err := client.data.Decrypt(oldEncryptedDuringOverlap); err != nil {
		t.Fatalf("expected old receive key to remain during overlap: %v", err)
	}
	if err := server.Rekey(serverKeys2, CipherAES128GCM, AuthSHA256, 7, ""); err != nil {
		t.Fatal(err)
	}
	newPacket := []byte{0x45, 0, 0, 20, 1, 2, 3, 5, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1}
	newEncrypted, err := server.Encrypt(newPacket)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(client.config.TransitionWindow + 20*time.Millisecond)

	if _, err := client.data.Decrypt(oldEncryptedAfterOverlap); err == nil {
		t.Fatal("expected old receive key to be retired after overlap")
	}
	if _, err := client.data.Decrypt(newEncrypted); err != nil {
		t.Fatalf("expected active receive key to remain after overlap: %v", err)
	}
}

func TestClientUsesOpenVPNTransitionWindowByDefault(t *testing.T) {
	client := &Client{config: &ClientConfig{}}
	if got := client.transitionWindow(); got != DefaultTransitionWindow {
		t.Fatalf("unexpected default transition window: %s", got)
	}
}

func TestClientBoundsDataKeyActivationDelay(t *testing.T) {
	tests := []struct {
		name   string
		config ClientConfig
		want   time.Duration
	}{
		{name: "default handshake window", config: ClientConfig{}, want: DefaultHandshakeTimeout},
		{name: "half renegotiate interval", config: ClientConfig{RenegotiateAfter: 45 * time.Second}, want: 22500 * time.Millisecond},
		{name: "half transition window", config: ClientConfig{TransitionWindow: 20 * time.Millisecond}, want: 10 * time.Millisecond},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &Client{config: &test.config}
			if got := client.dataKeyActivationDelay(); got != test.want {
				t.Fatalf("unexpected activation delay: got %s want %s", got, test.want)
			}
		})
	}
}

func TestClientAppliesLocalRenegotiateOverride(t *testing.T) {
	client := &Client{config: &ClientConfig{RenegotiateAfter: 45 * time.Second}}
	push := &PushReply{RenegotiateAfter: time.Hour}
	client.applyLocalTimingOverrides(push)
	if push.RenegotiateAfter != 45*time.Second {
		t.Fatalf("unexpected renegotiate interval: %s", push.RenegotiateAfter)
	}
}

func TestClientReadIPPacketFallsBackAfterConsecutiveDecryptErrors(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{
		RemoteHost: "127.0.0.1",
		RemotePort: 1194,
	}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	keys := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x11}, 16),
		SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x33}, 16),
		RecvHMACKey:   bytes.Repeat([]byte{0x44}, maxHMACKeyLength),
	}
	client.data, err = NewDataChannel(keys, CipherAES128GCM, AuthSHA256, 7, "")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	invalid := []byte{opcodeKeyID(PDataV1, 7)}
	for i := 0; i < maxConsecutiveDataDecryptErrors; i++ {
		if err := serverIO.WritePacket(ctx, invalid); err != nil {
			t.Fatal(err)
		}
	}

	_, err = client.ReadIPPacket(ctx)
	if !errors.Is(err, ErrControlRestart) {
		t.Fatalf("expected reconnect fallback after decrypt failures, got %v", err)
	}
	if got := client.activity.Snapshot().DataDecryptErrors; got != maxConsecutiveDataDecryptErrors {
		t.Fatalf("unexpected decrypt error count: %d", got)
	}
}

func TestRunControlLoopSendsPing(t *testing.T) {
	stream := newFakeControlStream()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runControlLoop(ctx, stream, &PushReply{
			PingInterval: 20 * time.Millisecond,
			PingRestart:  200 * time.Millisecond,
		}, "test", newRemoteActivity())
	}()

	select {
	case msg := <-stream.writeCh:
		if got := string(msg); got != "PING\x00" {
			t.Fatalf("unexpected ping payload: %q", got)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("control loop did not send PING")
	}

	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestRunControlLoopRestartsOnPingTimeout(t *testing.T) {
	stream := newFakeControlStream()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := runControlLoop(ctx, stream, &PushReply{PingRestart: 30 * time.Millisecond}, "test", newRemoteActivity())
	if !errors.Is(err, ErrControlRestart) {
		t.Fatalf("expected restart on ping timeout, got %v", err)
	}
	if !strings.Contains(err.Error(), "ping-restart") {
		t.Fatalf("expected ping-restart reason, got %v", err)
	}
	if !strings.Contains(err.Error(), "without remote activity") {
		t.Fatalf("expected remote activity reason, got %v", err)
	}
	if !strings.Contains(err.Error(), "last-control=never") || !strings.Contains(err.Error(), "last-data=never") {
		t.Fatalf("expected control/data activity diagnostics, got %v", err)
	}
}

func TestRemoteActivitySnapshotTracksControlDataAndDecryptErrors(t *testing.T) {
	activity := newRemoteActivity()
	activity.MarkControl()
	activity.MarkDataDecryptError()
	activity.MarkData()

	snapshot := activity.Snapshot()
	if snapshot.LastAny.IsZero() {
		t.Fatal("expected last activity timestamp")
	}
	if snapshot.LastControl.IsZero() {
		t.Fatal("expected last control activity timestamp")
	}
	if snapshot.LastData.IsZero() {
		t.Fatal("expected last data activity timestamp")
	}
	if snapshot.DataPackets != 1 {
		t.Fatalf("expected one inbound data packet, got %d", snapshot.DataPackets)
	}
	if snapshot.DataDecryptErrors != 1 {
		t.Fatalf("expected one data decrypt error, got %d", snapshot.DataDecryptErrors)
	}
}

func TestNegotiateDataChannelOptions(t *testing.T) {
	client := &Client{config: &ClientConfig{
		Cipher: CipherAES256CBC,
		Auth:   AuthSHA1,
	}}
	cipherName, authName, err := client.negotiateDataChannelOptions(
		&KeyMethod2Record{Options: "V4,cipher AES-128-GCM,auth SHA256,tls-server"},
		&PushReply{Cipher: CipherAES256GCM},
	)
	if err != nil {
		t.Fatal(err)
	}
	if cipherName != CipherAES256GCM {
		t.Fatalf("expected pushed cipher to win, got %s", cipherName)
	}
	if authName != AuthSHA256 {
		t.Fatalf("expected server auth option, got %s", authName)
	}
}

func TestRunControlLoopRekeysOnRenegSec(t *testing.T) {
	stream := newFakeControlStream()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rekeys := 0
	err := runControlLoopWithHooks(ctx, stream, &PushReply{RenegotiateAfter: time.Millisecond}, "test", newRemoteActivity(), controlLoopHooks{
		rekey: func(context.Context, string) (*PushReply, controlStream, error) {
			rekeys++
			cancel()
			return &PushReply{RenegotiateAfter: time.Hour}, stream, nil
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation after successful rekey, got %v", err)
	}
	if rekeys != 1 {
		t.Fatalf("expected one in-place rekey, got %d", rekeys)
	}
}

func TestRunControlLoopFallsBackWhenRekeyFails(t *testing.T) {
	stream := newFakeControlStream()
	err := runControlLoopWithHooks(context.Background(), stream, &PushReply{RenegotiateAfter: time.Millisecond}, "test", newRemoteActivity(), controlLoopHooks{
		rekey: func(context.Context, string) (*PushReply, controlStream, error) {
			return nil, nil, errors.New("boom")
		},
	})
	if !errors.Is(err, ErrControlRestart) {
		t.Fatalf("expected reconnect fallback, got %v", err)
	}
	if !strings.Contains(err.Error(), "rekey failed") {
		t.Fatalf("expected rekey failure reason, got %v", err)
	}
}

func TestRunControlLoopRekeysOnServerSoftRestartMessage(t *testing.T) {
	stream := newFakeControlStream()
	stream.readCh <- []byte("RESTART,soft\x00")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rekeys := 0
	err := runControlLoopWithHooks(ctx, stream, &PushReply{}, "test", newRemoteActivity(), controlLoopHooks{
		rekey: func(context.Context, string) (*PushReply, controlStream, error) {
			rekeys++
			cancel()
			return &PushReply{RenegotiateAfter: time.Hour}, stream, nil
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation after successful soft restart rekey, got %v", err)
	}
	if rekeys != 1 {
		t.Fatalf("expected one in-place rekey, got %d", rekeys)
	}
}

func TestRunControlLoopRekeysOnServerSoftResetPacket(t *testing.T) {
	stream := newOneShotReadErrorStream(fmt.Errorf("%w: %w: received P_CONTROL_SOFT_RESET_V1", ErrControlRestart, ErrControlSoftReset))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rekeys := 0
	err := runControlLoopWithHooks(ctx, stream, &PushReply{}, "test", newRemoteActivity(), controlLoopHooks{
		rekey: func(context.Context, string) (*PushReply, controlStream, error) {
			rekeys++
			cancel()
			return &PushReply{RenegotiateAfter: time.Hour}, stream, nil
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation after successful soft reset rekey, got %v", err)
	}
	if rekeys != 1 {
		t.Fatalf("expected one in-place rekey, got %d", rekeys)
	}
}

func TestRunControlLoopRestartsOnServerHardRestartMessage(t *testing.T) {
	stream := newFakeControlStream()
	stream.readCh <- []byte("HALT,server-exit\x00")

	err := runControlLoop(context.Background(), stream, &PushReply{}, "test", newRemoteActivity())
	if !errors.Is(err, ErrControlRestart) {
		t.Fatalf("expected restart on server HALT, got %v", err)
	}
}

func TestRunControlLoopReturnsAuthFailure(t *testing.T) {
	stream := newFakeControlStream()
	stream.readCh <- []byte("AUTH_FAILED,denied\x00")

	err := runControlLoop(context.Background(), stream, &PushReply{}, "test", newRemoteActivity())
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("expected auth failure, got %v", err)
	}
}

func TestRunControlLoopDataActivityPreventsPingRestart(t *testing.T) {
	stream := newFakeControlStream()
	activity := newRemoteActivity()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runControlLoop(ctx, stream, &PushReply{PingRestart: 60 * time.Millisecond}, "test", activity)
	}()

	time.Sleep(40 * time.Millisecond)
	activity.MarkData()

	select {
	case err := <-errCh:
		t.Fatalf("control loop stopped despite data-channel activity: %v", err)
	case <-time.After(40 * time.Millisecond):
	}

	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}
