package main

import (
	"errors"
	"math/rand"
)

// headerLen is the fixed size, in bytes, of the leading template that is
// written in front of every datagram's payload. Both peers agree on this
// length; the receiver simply skips it before handing the rest to the
// authenticated-decryption layer.
const headerLen = 37

// labelBytes fills a buffer with lowercase ASCII so each template instance
// differs on the wire instead of being byte-for-byte identical.
func labelBytes(dst []byte) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	for i := range dst {
		dst[i] = alphabet[rand.Intn(len(alphabet))]
	}
}

// writeHeader renders a fresh template into the first headerLen bytes of dst.
// The leading two bytes are a per-datagram random tag; the remainder is a
// fixed scaffold with two variable-content fields.
func writeHeader(dst []byte) {
	_ = dst[headerLen-1] // bounds hint

	dst[0] = byte(rand.Intn(256))
	dst[1] = byte(rand.Intn(256))

	dst[2], dst[3] = 0x01, 0x00
	dst[4], dst[5] = 0x00, 0x01
	dst[6], dst[7] = 0x00, 0x00
	dst[8], dst[9] = 0x00, 0x00
	dst[10], dst[11] = 0x00, 0x00

	dst[12] = 0x0f
	labelBytes(dst[13:28])
	dst[28] = 0x03
	labelBytes(dst[29:32])
	dst[32] = 0x00

	dst[33], dst[34] = 0x00, 0x01
	dst[35], dst[36] = 0x00, 0x01
}

// frame wraps an already-sealed payload with a new template header.
func frame(sealed []byte) []byte {
	out := make([]byte, headerLen+len(sealed))
	writeHeader(out[:headerLen])
	copy(out[headerLen:], sealed)
	return out
}

// deframe strips the leading template and returns the sealed payload.
func deframe(pkt []byte) ([]byte, error) {
	if len(pkt) < headerLen {
		return nil, errors.New("runt datagram")
	}
	return pkt[headerLen:], nil
}
