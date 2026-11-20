package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

// sealer provides authenticated encryption for the payload portion of every
// datagram. A 256-bit key is derived from the shared secret.
type sealer struct {
	aead cipher.AEAD
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
	return &sealer{aead: aead}, nil
}

func (s *sealer) nonceSize() int { return s.aead.NonceSize() }

// seal encrypts plaintext and returns nonce||ciphertext.
func (s *sealer) seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := s.aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, out...), nil
}

// open reverses seal; input must be nonce||ciphertext.
func (s *sealer) open(data []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	if len(data) < ns {
		return nil, errors.New("short payload")
	}
	return s.aead.Open(nil, data[:ns], data[ns:], nil)
}
