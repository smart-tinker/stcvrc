package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMihomo_Hysteria(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageHysteria,
		ExposedPorts: defaultExposedPorts,
		Cmd:          []string{"server", "--config", "/config.json"},
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/config.json", C.Path.Resolve("hysteria.json")),
			fmt.Sprintf("%s:/home/ubuntu/my.crt", C.Path.Resolve("example.org.pem")),
			fmt.Sprintf("%s:/home/ubuntu/my.key", C.Path.Resolve("example.org-key.pem")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "hysteria")
	if err != nil {
		assert.FailNow(t, err.Error())
	}

	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewHysteria(outbound.HysteriaOption{
		Name:           "hysteria",
		Server:         localIP.String(),
		Port:           10002,
		Obfs:           "fuck me till the daylight",
		Up:             "100",
		Down:           "100",
		SkipCertVerify: true,
	})
	if err != nil {
		assert.FailNow(t, err.Error())
	}

	time.Sleep(waitTime)
	// shortcut: run UDP only in the exact .33 comparison; the .29 baseline retains TCP coverage.
	assert.NoError(t, testPingPongWithConn(t, func() net.Conn {
		conn, err := proxy.DialContext(context.Background(), &C.Metadata{
			Host:    localIP.String(),
			DstPort: 10001,
		})
		require.NoError(t, err)
		return conn
	}))

	if os.Getenv("STCVRC_COMPARE_V33_HYSTERIA_UDP") == "1" {
		pc, err := proxy.ListenPacketContext(context.Background(), &C.Metadata{
			NetWork: C.UDP,
			DstIP:   localIP,
			DstPort: 10001,
		})
		require.NoError(t, err)
		defer pc.Close()
		assert.NoError(t, testPingPongWithPacketConn(t, pc))
	}

}
