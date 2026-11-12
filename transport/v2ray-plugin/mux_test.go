package obfs

import (
	"bytes"
	"net"
	"testing"
)

type oneByteReadConn struct {
	net.Conn
	reader *bytes.Reader
}

func (c *oneByteReadConn) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return c.reader.Read(p)
}

func TestMuxReadHandlesShortStatusHeader(t *testing.T) {
	frame := []byte{0x00, 0x04, 0x00, 0x00, 0x02, 0x01, 0x00, 0x01, 'x'}
	mux := &Mux{Conn: &oneByteReadConn{reader: bytes.NewReader(frame)}}

	got := make([]byte, 1)
	n, err := mux.Read(got)
	if err != nil {
		t.Fatalf("Mux.Read() error = %v, want payload %q", err, "x")
	}
	if n != 1 || got[0] != 'x' {
		t.Fatalf("Mux.Read() = (%d, %q), want (1, %q)", n, got, "x")
	}
}
