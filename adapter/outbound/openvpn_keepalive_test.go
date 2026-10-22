package outbound

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	ovpn "github.com/metacubex/mihomo/transport/openvpn"
	"golang.org/x/sync/semaphore"
)

type idleOpenVPNPacketIO struct {
	closed chan struct{}
	once   sync.Once
}

func (p *idleOpenVPNPacketIO) ReadPacket() ([]byte, error) {
	<-p.closed
	return nil, net.ErrClosed
}

func (p *idleOpenVPNPacketIO) WritePacket([]byte) error { return nil }
func (p *idleOpenVPNPacketIO) LocalAddr() net.Addr      { return nil }
func (p *idleOpenVPNPacketIO) RemoteAddr() net.Addr     { return nil }
func (p *idleOpenVPNPacketIO) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

func TestOpenVPNPushedKeepaliveTearsDownAndReactivatesAdapter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	o := &OpenVPN{
		Base:   NewBase(BaseOption{Name: "keepalive-test"}),
		config: &ovpn.ClientConfig{},
		runCtx: ctx, runCancel: cancel, runLock: semaphore.NewWeighted(1),
	}
	t.Cleanup(func() { _ = o.Close() })
	activate := func(push *ovpn.PushReply) (*idleOpenVPNPacketIO, ipStack) {
		t.Helper()
		packetIO := &idleOpenVPNPacketIO{closed: make(chan struct{})}
		client, err := ovpn.NewClient(o.config, packetIO)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		option := IPStackOption{}
		option.normalize()
		stack, err := newIPStack(option, []netip.Prefix{netip.MustParsePrefix("10.203.0.2/24")}, 1500)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = stack.Close() })
		if err := stack.Start(); err != nil {
			t.Fatal(err)
		}
		if err := o.runLock.Acquire(ctx, 1); err != nil {
			t.Fatal(err)
		}
		o.client, o.tunDevice, o.running = client, stack, true
		o.startPacketLoops(push)
		o.runLock.Release(1)
		return packetIO, stack
	}
	push, err := ovpn.ParsePushReply("PUSH_REPLY,ifconfig 10.203.0.2 255.255.255.0,ping-restart 1")
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	firstIO, _ := activate(push)
	deadline := time.Now().Add(3 * time.Second)
	stopped := false
	for time.Now().Before(deadline) {
		if err := o.runLock.Acquire(ctx, 1); err != nil {
			t.Fatal(err)
		}
		stopped = !o.running && o.client == nil && o.tunDevice == nil
		o.runLock.Release(1)
		if stopped {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !stopped {
		t.Fatal("pushed idle timeout did not clear adapter state")
	}
	if time.Since(started) < 800*time.Millisecond {
		t.Fatal("adapter stopped before the keepalive timeout")
	}
	select {
	case <-firstIO.closed:
	default:
		t.Fatal("timed-out packet transport was not closed")
	}
	if ctx.Err() != nil {
		t.Fatal("idle timeout canceled the reusable adapter context")
	}
	secondIO, secondStack := activate(nil)
	time.Sleep(50 * time.Millisecond)
	if err := o.runLock.Acquire(ctx, 1); err != nil {
		t.Fatal(err)
	}
	reactivated := o.running && o.client != nil && o.tunDevice == secondStack
	o.runLock.Release(1)
	if !reactivated {
		t.Fatal("old cleanup cleared the replacement session")
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-secondIO.closed:
	default:
		t.Fatal("adapter close left the replacement transport open")
	}
}
