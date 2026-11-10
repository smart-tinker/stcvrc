package openvpn

import (
	"errors"

	"github.com/anchore/go-lzo"
)

const (
	lzoCompressNone = 0xFA // not compressed
	lzoCompressLZO  = 0x66 // LZO compressed

	maxOpenVPNIPPacketSize = 65575
)

var ErrLZODecompress = errors.New("lzo decompression failed")

// lzo1xDecompressSafe handles OpenVPN comp-lzo data packets.
// First byte is the compression header, followed by the payload.
func lzo1xDecompressSafe(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, ErrLZODecompress
	}

	switch src[0] {
	case lzoCompressNone:
		if len(src) > 1 {
			return src[1:], nil
		}
		return nil, nil
	case lzoCompressLZO:
		if len(src) > 1 {
			payload := src[1:]
			size := len(payload)
			if size < 1500 {
				size = 1500
			}
			if size > maxOpenVPNIPPacketSize {
				size = maxOpenVPNIPPacketSize
			}
			for {
				out := make([]byte, size)
				n, err := lzo.Decompress(payload, out)
				if err == nil {
					return out[:n], nil
				}
				if !errors.Is(err, lzo.ErrOutputOverrun) || size == maxOpenVPNIPPacketSize {
					return nil, ErrLZODecompress
				}
				return nil, ErrLZODecompress
				if size > maxOpenVPNIPPacketSize/2 {
					size = maxOpenVPNIPPacketSize
				} else {
					size *= 2
				}
			}
		}
		return nil, nil
	default:
		return nil, ErrLZODecompress
	}
}

// lzo1xCompressSafe handles OpenVPN comp-lzo data packets.
// Prepend comp-lzo header (0xfa = not compressed) to satisfy servers expecting the framing.
func lzo1xCompressSafe(src []byte) ([]byte, error) {
	lzoPacket := make([]byte, 1+len(src))
	lzoPacket[0] = lzoCompressNone
	copy(lzoPacket[1:], src)
	return lzoPacket, nil
}
