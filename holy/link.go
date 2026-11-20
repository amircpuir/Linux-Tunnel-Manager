package main

import (
	"log"
	"net"
	"sync/atomic"
	"time"
)

const maxPkt = 2048

// link carries inner IP packets between a local TUN interface and a remote
// peer over UDP, wrapping each one with a fixed leading header. No encryption:
// the payload is the raw IP packet, so the data path is a header stamp plus two
// syscalls with zero per-packet copies.
type link struct {
	cfg  *Config
	tun  *tunDevice
	conn *net.UDPConn
	fr   *framer

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

func (l *link) writeOut(pkt []byte) {
	if l.cfg.Role == "client" {
		l.conn.Write(pkt)
		return
	}
	if dst := l.getPeer(); dst != nil {
		l.conn.WriteToUDP(pkt, dst)
	}
}

// tunToNet reads raw IP packets from the interface and forwards them. The
// packet is read straight into the buffer past the header, so stamping the
// header and sending needs no payload copy.
func (l *link) tunToNet() {
	buf := make([]byte, headerLen+maxPkt)
	for {
		n, err := l.tun.Read(buf[headerLen:])
		if err != nil {
			log.Printf("tun read: %v", err)
			return
		}
		if l.cfg.Role == "server" && l.getPeer() == nil {
			continue // no client has checked in yet
		}
		l.fr.stamp(buf[:headerLen])
		l.writeOut(buf[:headerLen+n])
	}
}

// netToTun reads datagrams, checks the marker, and writes the inner packet
// straight to TUN (no copy).
func (l *link) netToTun() {
	buf := make([]byte, headerLen+maxPkt)
	for {
		var (
			n   int
			src *net.UDPAddr
			err error
		)
		if l.cfg.Role == "client" {
			n, err = l.conn.Read(buf)
		} else {
			n, src, err = l.conn.ReadFromUDP(buf)
		}
		if err != nil {
			log.Printf("udp read: %v", err)
			return
		}
		if !l.fr.valid(buf[:n]) {
			continue // not ours
		}
		if l.cfg.Role == "server" && src != nil {
			l.setPeer(src)
		}
		if n == headerLen {
			continue // keepalive (header only)
		}
		l.tun.Write(buf[headerLen:n])
	}
}

// keepalive maintains the UDP path from the client side with header-only
// datagrams.
func (l *link) keepalive() {
	if l.cfg.Role != "client" || l.cfg.Keepalive <= 0 {
		return
	}
	buf := make([]byte, headerLen)
	t := time.NewTicker(time.Duration(l.cfg.Keepalive) * time.Second)
	defer t.Stop()
	for range t.C {
		l.fr.stamp(buf)
		l.writeOut(buf)
	}
}

// prime sends one header-only datagram so the far side learns our address.
func (l *link) prime() {
	buf := make([]byte, headerLen)
	l.fr.stamp(buf)
	l.writeOut(buf)
}
