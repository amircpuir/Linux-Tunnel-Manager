package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
)

// Build-time version string (overridden via -ldflags).
var version = "dev"

func runCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %v (%s)", name, args, err, string(out))
	}
	return nil
}

// bringUp assigns the inner address and activates the interface.
func bringUp(cfg *Config, dev string) error {
	runCmd("ip", "addr", "flush", "dev", dev)
	if err := runCmd("ip", "addr", "add",
		fmt.Sprintf("%s/%d", cfg.TunIP, cfg.Prefix), "dev", dev); err != nil {
		return err
	}
	if err := runCmd("ip", "link", "set", "dev", dev,
		"mtu", strconv.Itoa(cfg.MTU), "up"); err != nil {
		return err
	}
	// A longer queue absorbs bursts before packets are dropped at the device.
	runCmd("ip", "link", "set", "dev", dev, "txqueuelen", "10000")
	// Ensure the peer's inner address routes back over the interface.
	runCmd("ip", "route", "replace", cfg.PeerIP+"/32", "dev", dev, "src", cfg.TunIP)
	runCmd("sysctl", "-w", "net.ipv4.ip_forward=1")
	runCmd("sysctl", "-w", "net.ipv4.conf."+dev+".rp_filter=0")
	return nil
}

func main() {
	cfgPath := flag.String("config", "/etc/holy-tunnel/config.json", "path to the config file")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVer {
		fmt.Println(version)
		return
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	sl, err := newSealer(cfg.Secret)
	if err != nil {
		log.Fatalf("crypto: %v", err)
	}

	tun, err := openTUN(cfg.TunName)
	if err != nil {
		log.Fatalf("tun: %v", err)
	}
	defer tun.Close()

	if err := bringUp(cfg, tun.name); err != nil {
		log.Fatalf("interface: %v", err)
	}
	log.Printf("holy %s: interface %s is up (%s/%d mtu %d, role %s)",
		version, tun.name, cfg.TunIP, cfg.Prefix, cfg.MTU, cfg.Role)

	l := &link{cfg: cfg, tun: tun, sl: sl}

	switch cfg.Role {
	case "server":
		addr, err := net.ResolveUDPAddr("udp", cfg.Listen)
		if err != nil {
			log.Fatalf("listen address: %v", err)
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			log.Fatalf("listen: %v", err)
		}
		l.conn = conn
		log.Printf("listening on %s", cfg.Listen)
	case "client":
		raddr, err := net.ResolveUDPAddr("udp", cfg.Remote)
		if err != nil {
			log.Fatalf("remote address: %v", err)
		}
		var laddr *net.UDPAddr
		if cfg.Local != "" {
			if ip := net.ParseIP(cfg.Local); ip != nil {
				laddr = &net.UDPAddr{IP: ip}
			}
		}
		conn, err := net.DialUDP("udp", laddr, raddr)
		if err != nil {
			log.Fatalf("dial: %v", err)
		}
		l.conn = conn
		log.Printf("target %s", cfg.Remote)
		// Prime the path so the far side learns our source address.
		l.send([]byte{typKeepalive})
	}
	// Large socket buffers absorb TCP bursts; without them the kernel silently
	// drops datagrams under load, which collapses throughput. The kernel cap is
	// raised separately via sysctl (rmem_max/wmem_max).
	if err := l.conn.SetReadBuffer(16 << 20); err != nil {
		log.Printf("set read buffer: %v", err)
	}
	if err := l.conn.SetWriteBuffer(16 << 20); err != nil {
		log.Printf("set write buffer: %v", err)
	}
	defer l.conn.Close()

	go l.tunToNet()
	go l.keepalive()
	l.netToTun() // blocks for the lifetime of the process
}
