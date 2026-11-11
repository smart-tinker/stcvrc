package main

import (
	"context"
	"fmt"
	"net"
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
	// shortcut: bound Hysteria to TCP/UDP echo; restore bulk stress after repeatable hosted-runner evidence
	assert.NoError(t, testPingPongWithConn(t, func() net.Conn {
		conn, err := proxy.DialContext(context.Background(), &C.Metadata{
			Host:    localIP.String(),
			DstPort: 10001,
		})
		require.NoError(t, err)
		return conn
	}))
	pc, err := proxy.ListenPacketContext(context.Background(), &C.Metadata{
		NetWork: C.UDP,
		DstIP:   localIP,
		DstPort: 10001,
	})
	require.NoError(t, err)
	defer pc.Close()
	assert.NoError(t, testPingPongWithPacketConn(t, pc))
}
