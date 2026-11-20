package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync/atomic"
)

// sealer provides authenticated encryption for the payload portion of every
// datagram. A 256-bit key is derived from the shared secret.
//
// The 12-byte nonce is formed from an 8-byte random salt chosen once per
// process plus a 4-byte monotonic counter, so no RNG syscall is needed on the
// hot path. The salt is re-randomised on every (re)start, which keeps nonces
// unique even when the same long-lived key is reused across restarts.
type sealer struct {
	aead    cipher.AEAD
	salt    [8]byte
	counter atomic.Uint32
}

func newSealer(secret string) (*sealer, error) {
	key := sha256.Sum256([]byte("holy-v1:" + secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &sealer{aead: aead}
	if _, err := io.ReadFull(rand.Reader, s.salt[:]); err != nil {
		return nil, err
	}
	return s, nil
}

const nonceLen = 12

// sealInto writes nonce||ciphertext into dst (appending) and returns the
// extended slice. No per-call heap allocation when dst has enough capacity.
func (s *sealer) sealInto(dst, plaintext []byte) []byte {
	var nonce [nonceLen]byte
	copy(nonce[:8], s.salt[:])
	binary.BigEndian.PutUint32(nonce[8:], s.counter.Add(1))

	dst = append(dst, nonce[:]...)
	return s.aead.Seal(dst, nonce[:], plaintext, nil)
}

// open reverses sealInto; input must be nonce||ciphertext. The plaintext is
// appended to dst (which may be dst[:0] of a reusable buffer).
func (s *sealer) open(dst, data []byte) ([]byte, error) {
	if len(data) < nonceLen {
		return nil, errors.New("short payload")
	}
	return s.aead.Open(dst, data[:nonceLen], data[nonceLen:], nil)
}
