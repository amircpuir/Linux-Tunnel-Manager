package main

import (
	"log"
	"net"
	"sync"
	"time"
)

const (
	typData      = 0x00
	typKeepalive = 0x01
	maxPkt       = 2048
)

// link carries inner IP packets between a local TUN interface and a remote
// peer over UDP, sealing every payload and wrapping it with a template header.
type link struct {
	cfg  *Config
	tun  *tunDevice
	conn *net.UDPConn
	sl   *sealer

	mu   sync.RWMutex
	peer *net.UDPAddr // server side: the client's current source address
}

func (l *link) setPeer(a *net.UDPAddr) {
	l.mu.Lock()
	if l.peer == nil || l.peer.String() != a.String() {
		l.peer = a
		log.Printf("peer address learned: %s", a.String())
	}
	l.mu.Unlock()
}

func (l *link) getPeer() *net.UDPAddr {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.peer
}

func (l *link) send(plain []byte) {
	sealed, err := l.sl.seal(plain)
	if err != nil {
		return
	}
	pkt := frame(sealed)
	if l.cfg.Role == "client" {
		l.conn.Write(pkt)
		return
	}
	if dst := l.getPeer(); dst != nil {
		l.conn.WriteToUDP(pkt, dst)
	}
}

// tunToNet reads raw IP packets from the interface and forwards them.
func (l *link) tunToNet() {
	buf := make([]byte, maxPkt)
	for {
		n, err := l.tun.Read(buf)
		if err != nil {
			log.Printf("tun read: %v", err)
			return
		}
		if l.cfg.Role == "server" && l.getPeer() == nil {
			continue // no client has checked in yet
		}
		plain := make([]byte, n+1)
		plain[0] = typData
		copy(plain[1:], buf[:n])
		l.send(plain)
	}
}

// netToTun reads datagrams, verifies them, and writes inner packets to TUN.
func (l *link) netToTun() {
	buf := make([]byte, maxPkt)
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

		sealed, err := deframe(buf[:n])
		if err != nil {
			continue
		}
		plain, err := l.sl.open(sealed)
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
