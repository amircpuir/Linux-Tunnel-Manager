package main

import (
	"log"
	"net"
	"sync/atomic"
	"time"
)

const (
	typData      = 0x00
	typKeepalive = 0x01
	maxPkt       = 2048
	outCap       = headerLen + nonceLen + maxPkt + 32 // header + nonce + payload + GCM tag
)

// link carries inner IP packets between a local TUN interface and a remote
// peer over UDP, sealing every payload and wrapping it with a template header.
type link struct {
	cfg  *Config
	tun  *tunDevice
	conn *net.UDPConn
	sl   *sealer

	peer atomic.Pointer[net.UDPAddr] // server side: the client's current source
}

func (l *link) setPeer(a *net.UDPAddr) {
	cur := l.peer.Load()
	if cur == nil || cur.Port != a.Port || !cur.IP.Equal(a.IP) {
		l.peer.Store(a)
		log.Printf("peer address learned: %s", a.String())
	}
}

func (l *link) getPeer() *net.UDPAddr { return l.peer.Load() }

// buildDatagram lays out [header | nonce | sealed payload] into dst's backing
// array (no heap allocation when dst has enough capacity) and returns it.
func (l *link) buildDatagram(dst, plain []byte) []byte {
	dst = dst[:headerLen]
	writeHeaderInto(dst)
	return l.sl.sealInto(dst, plain)
}

func (l *link) writeOut(pkt []byte) {
	if l.cfg.Role == "client" {
		l.conn.Write(pkt)
		return
	}
	if dst := l.getPeer(); dst != nil {
		l.conn.WriteToUDP(pkt, dst)
	}
}

// send builds and transmits a single payload. Used for low-rate control
// traffic (keepalive / path priming); the bulk path uses tunToNet directly.
func (l *link) send(plain []byte) {
	out := make([]byte, 0, outCap)
	l.writeOut(l.buildDatagram(out, plain))
}

// tunToNet reads raw IP packets from the interface and forwards them. It owns
// its buffers, so the steady state does zero per-packet heap allocation.
func (l *link) tunToNet() {
	readBuf := make([]byte, maxPkt)
	plainBuf := make([]byte, maxPkt+1)
	outBuf := make([]byte, 0, outCap)

	for {
		n, err := l.tun.Read(readBuf)
		if err != nil {
			log.Printf("tun read: %v", err)
			return
		}
		if l.cfg.Role == "server" && l.getPeer() == nil {
			continue // no client has checked in yet
		}
		plainBuf[0] = typData
		copy(plainBuf[1:], readBuf[:n])
		l.writeOut(l.buildDatagram(outBuf, plainBuf[:1+n]))
	}
}

// netToTun reads datagrams, verifies them, and writes inner packets to TUN.
func (l *link) netToTun() {
	recvBuf := make([]byte, maxPkt)
	openBuf := make([]byte, 0, maxPkt)

	for {
		var (
			n   int
			src *net.UDPAddr
			err error
		)
		if l.cfg.Role == "client" {
			n, err = l.conn.Read(recvBuf)
		} else {
			n, src, err = l.conn.ReadFromUDP(recvBuf)
		}
		if err != nil {
			log.Printf("udp read: %v", err)
			return
		}

		sealed, err := deframe(recvBuf[:n])
		if err != nil {
			continue
		}
		plain, err := l.sl.open(openBuf[:0], sealed)
		if err != nil {
			continue // not authentic — ignore silently
		}

		if l.cfg.Role == "server" && src != nil {
			l.setPeer(src)
		}
		if len(plain) < 1 {
			continue
		}
		switch plain[0] {
		case typKeepalive:
			// path-maintenance only
		case typData:
			l.tun.Write(plain[1:])
		}
	}
}

// keepalive maintains the UDP path from the client side.
func (l *link) keepalive() {
	if l.cfg.Role != "client" || l.cfg.Keepalive <= 0 {
		return
	}
	t := time.NewTicker(time.Duration(l.cfg.Keepalive) * time.Second)
	defer t.Stop()
	for range t.C {
		l.send([]byte{typKeepalive})
	}
}
