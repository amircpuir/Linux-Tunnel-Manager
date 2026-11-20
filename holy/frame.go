package main

import (
	"errors"
	"math/rand"
	"sync/atomic"
)

// headerLen is the fixed size, in bytes, of the leading template that is
// written in front of every datagram's payload. Both peers agree on this
// length; the receiver simply skips it before handing the rest to the
// authenticated-decryption layer.
const headerLen = 37

// headerTemplate is built once at startup. Every datagram reuses it and only
// overwrites the first two bytes with a per-datagram tag, so the hot path does
// no locked global-RNG work.
var headerTemplate [headerLen]byte

// headerTag is a free-running counter used for the two variable leading bytes.
var headerTag atomic.Uint32

func init() {
	buildTemplate(headerTemplate[:])
	headerTag.Store(rand.Uint32())
}

// labelBytes fills a buffer with lowercase ASCII so the template is not a
// fixed, well-known byte string.
func labelBytes(dst []byte) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	for i := range dst {
		dst[i] = alphabet[rand.Intn(len(alphabet))]
	}
}

// buildTemplate renders the fixed scaffold once. The first two bytes are left
// as zero; they are set per datagram by writeHeaderInto.
func buildTemplate(dst []byte) {
	dst[0], dst[1] = 0, 0
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

// writeHeaderInto copies the template into the first headerLen bytes of dst and
// stamps a fresh per-datagram tag. dst must have at least headerLen bytes.
func writeHeaderInto(dst []byte) {
	copy(dst[:headerLen], headerTemplate[:])
	t := headerTag.Add(1)
	dst[0] = byte(t)
	dst[1] = byte(t >> 8)
}

// deframe strips the leading template and returns the sealed payload.
func deframe(pkt []byte) ([]byte, error) {
	if len(pkt) < headerLen {
		return nil, errors.New("runt datagram")
	}
	return pkt[headerLen:], nil
}
