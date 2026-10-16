package openvpn

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestKeepaliveLZOOutboundFraming(t *testing.T) {
	for _, cipher := range []string{CipherAES128GCM, CipherAES128CBC} {
		t.Run(cipher, func(t *testing.T) {
			client, io, peer := newKeepaliveCipherPair(t, cipher)
			client.config.CompLZO = CompLzoYes
			if err := client.WritePing(context.Background()); err != nil {
				t.Fatal(err)
			}
			plain := readKeepalivePacket(t, io, peer)
			if len(plain) != len(openVPNPingPacket)+1 || plain[0] != lzoCompressNone || !IsPingPacket(plain[1:]) {
				t.Fatalf("ping lacks negotiated comp-lzo framing: %x", plain)
			}
		})
	}
}

func TestKeepaliveLZOInboundPingIsNotAnIPPacket(t *testing.T) {
	for _, cipher := range []string{CipherAES128GCM, CipherAES128CBC} {
		t.Run(cipher, func(t *testing.T) {
			client, io, peer := newKeepaliveCipherPair(t, cipher)
			client.config.CompLZO = CompLzoYes
			ip := []byte{0x45, 0, 0, 20}
			for _, payload := range [][]byte{openVPNPingPacket, ip} {
				framed := append([]byte{lzoCompressNone}, payload...)
				packet, err := peer.Encrypt(framed)
				if err != nil {
					t.Fatal(err)
				}
				if err := io.WritePacket(context.Background(), packet); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, err := client.ReadIPPacket(ctx)
			if err != nil || !bytes.Equal(got, ip) {
				t.Fatalf("compressed keepalive escaped into the IP stack: got=%x err=%v", got, err)
			}
		})
	}
}
