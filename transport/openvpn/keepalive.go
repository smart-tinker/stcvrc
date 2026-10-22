package openvpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

var ErrPingRestart = errors.New("ping-restart timeout")

// SendKeepalives sends encrypted pings only while the outbound link is idle.
// The caller owns teardown, so a blocked writer cannot delay the receive watchdog.
func (c *Client) SendKeepalives(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return errors.New("keepalive interval must be positive")
	}
	timer := time.NewTimer(interval - c.SinceSend())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.runCtx.Done():
			return net.ErrClosed
		case <-timer.C:
			if remaining := interval - c.SinceSend(); remaining > 0 {
				timer.Reset(remaining)
				continue
			}
			if err := c.WritePing(ctx); err != nil {
				return err
			}
			// A deliberately dropped write must not turn into an immediate retry loop.
			timer.Reset(interval)
		}
	}
}

// WaitPingRestart watches authenticated data and accepted control-channel activity.
func (c *Client) WaitPingRestart(ctx context.Context, timeout time.Duration) error {
	if timeout <= 0 {
		return errors.New("ping-restart interval must be positive")
	}
	timer := time.NewTimer(timeout - c.SinceReceive())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.runCtx.Done():
			return net.ErrClosed
		case <-timer.C:
			if idle := c.SinceReceive(); idle >= timeout {
				lastData := "never"
				if timestamp := c.lastDataPacketNano.Load(); timestamp != 0 {
					lastData = (time.Since(start) - time.Duration(timestamp)).Round(time.Second).String()
				}
				return fmt.Errorf("%w: no packet received for %s (last-send=%s, last-data-packet=%s, inbound-data-packets=%d, data-decrypt-errors=%d)",
					ErrPingRestart, idle.Round(time.Second), c.SinceSend().Round(time.Second), lastData,
					c.inboundDataPackets.Load(), c.dataDecryptErrors.Load())
			} else {
				timer.Reset(timeout - idle)
			}
		}
	}
}
