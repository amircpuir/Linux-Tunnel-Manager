package main

import (
	"crypto/sha256"
	"math/rand"
	"sync/atomic"
)

// headerLen is the fixed size, in bytes, of the leading template written in
// front of every datagram's payload. Both peers agree on this length; the
// receiver simply skips it to recover the inner packet. The template is shaped
// like a standard query header so on-path inspection classifies the datagram
// by its leading bytes rather than its contents.
const headerLen = 37

// tokenLen is how many bytes of the shared marker are embedded in, and checked
// from, each header. It is a recognition tag (not encryption): it lets a peer
// ignore unrelated traffic hitting the port and only learn addresses from its
// own datagrams.
const tokenLen = 6

// tokenOff is where the marker sits inside the first label region of the
// header (offset 13 begins the 15-byte label payload).
const tokenOff = 13

// framer stamps and validates the fixed leading header. It holds a template
// built once from the shared secret; the hot path only rewrites two tag bytes.
type framer struct {
	template [headerLen]byte
	token    [tokenLen]byte
	tag      atomic.Uint32
}

func newFramer(secret string) *framer {
	f := &framer{}
	sum := sha256.Sum256([]byte("holy-tag:" + secret))
	copy(f.token[:], sum[:tokenLen])
	f.buildTemplate()
	f.tag.Store(rand.Uint32())
	return f
}

// labelBytes fills a buffer with lowercase ASCII so the template is not a
// fixed, well-known byte string.
func labelBytes(dst []byte) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	for i := range dst {
		dst[i] = alphabet[rand.Intn(len(alphabet))]
	}
}

// buildTemplate renders the fixed scaffold once. Bytes 0-1 are the per-datagram
// tag (left zero here); the shared marker is embedded in the first label.
func (f *framer) buildTemplate() {
	d := f.template[:]
	d[0], d[1] = 0, 0
	d[2], d[3] = 0x01, 0x00
	d[4], d[5] = 0x00, 0x01
	d[6], d[7] = 0x00, 0x00
	d[8], d[9] = 0x00, 0x00
	d[10], d[11] = 0x00, 0x00

	d[12] = 0x0f // first label length: 15
	labelBytes(d[13:28])
	copy(d[tokenOff:tokenOff+tokenLen], f.token[:])
	d[28] = 0x03 // second label length: 3
	labelBytes(d[29:32])
	d[32] = 0x00 // root label

	d[33], d[34] = 0x00, 0x01 // QTYPE
	d[35], d[36] = 0x00, 0x01 // QCLASS
}

// stamp writes the template into dst[:headerLen] with a fresh per-datagram tag.
func (f *framer) stamp(dst []byte) {
	copy(dst[:headerLen], f.template[:])
	t := f.tag.Add(1)
	dst[0] = byte(t)
	dst[1] = byte(t >> 8)
}

// valid reports whether pkt carries our marker and is long enough to be ours.
func (f *framer) valid(pkt []byte) bool {
	if len(pkt) < headerLen {
		return false
	}
	for i := 0; i < tokenLen; i++ {
		if pkt[tokenOff+i] != f.token[i] {
			return false
		}
	}
	return true
}
