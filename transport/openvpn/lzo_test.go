package openvpn

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestLzo1xSafe(t *testing.T) {
	data := make([]byte, 1024)
	rand.Read(data)
	compressed, err := lzo1xCompressSafe(data)
	if err != nil {
		t.Fatal(err)
	}
	decompressed, err := lzo1xDecompressSafe(compressed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decompressed) {
		t.Fatal("decompressed data is not equal to original")
	}
}

func TestLzo1xDecompressCompressedPayload(t *testing.T) {
	compressed := append([]byte{lzoCompressLZO, 0x1c}, []byte("hello world")...)
	compressed = append(compressed, 0x11, 0x00, 0x00)

	decompressed, err := lzo1xDecompressSafe(compressed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decompressed, []byte("hello world")) {
		t.Fatalf("decompressed payload = %q, want %q", decompressed, "hello world")
	}
}

func TestLzo1xDecompressGrowsOutputForCompressedRun(t *testing.T) {
	const decodedSize = 2048

	// One literal followed by an overlapping M3 match expands past the initial buffer.
	stream := []byte{18, 'A', 0x20}
	stream = append(stream, make([]byte, 7)...)
	stream = append(stream, 229, 0, 0, 0x11, 0, 0)
	packet := append([]byte{lzoCompressLZO}, stream...)

	decompressed, err := lzo1xDecompressSafe(packet)
	if err != nil {
		t.Fatal(err)
	}
	if want := bytes.Repeat([]byte{'A'}, decodedSize); !bytes.Equal(decompressed, want) {
		t.Fatalf("decompressed %d bytes, want %d repeated bytes", len(decompressed), len(want))
	}
}

func TestLzo1xDecompressRejectsOversizedPacket(t *testing.T) {
	const decodedSize = maxOpenVPNIPPacketSize + 1

	// LZO's extended literal length encodes 3 + 257*255 + 15 + 23 bytes.
	stream := []byte{0x00}
	stream = append(stream, bytes.Repeat([]byte{0x00}, 257)...)
	stream = append(stream, 23)
	stream = append(stream, bytes.Repeat([]byte{'x'}, decodedSize)...)
	stream = append(stream, 0x11, 0x00, 0x00)
	packet := append([]byte{lzoCompressLZO}, stream...)

	if _, err := lzo1xDecompressSafe(packet); err == nil {
		t.Fatalf("accepted decompressed packet larger than IPv6 maximum (%d bytes)", maxOpenVPNIPPacketSize)
	}
}
