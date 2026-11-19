package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config is the on-disk description of a single Holy endpoint. It is written
// by the manager and read back by the service on every (re)start, which is
// what makes the link survive reboots.
type Config struct {
	Role      string `json:"role"`       // "server" or "client"
	Listen    string `json:"listen"`     // server bind, host:port
	Remote    string `json:"remote"`     // client target, host:port
	Local     string `json:"local"`      // local source address to bind (optional)
	Secret    string `json:"secret"`     // shared key
	TunName   string `json:"tun_name"`   // interface name, e.g. holy0
	TunIP     string `json:"tun_ip"`     // local inner address, e.g. 10.200.0.1
	PeerIP    string `json:"peer_ip"`    // remote inner address, e.g. 10.200.0.2
	Prefix    int    `json:"prefix"`     // inner subnet prefix, default 30
	MTU       int    `json:"mtu"`        // TUN MTU
	Keepalive int    `json:"keepalive"`  // seconds between keepalives (client)
}

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.TunName == "" {
		c.TunName = "holy0"
	}
	if c.Prefix == 0 {
		c.Prefix = 30
	}
	if c.MTU == 0 {
		c.MTU = 1300
	}
	if c.Keepalive == 0 {
		c.Keepalive = 15
	}
	if c.Role != "server" && c.Role != "client" {
		return nil, fmt.Errorf("role must be server or client, got %q", c.Role)
	}
	if c.Secret == "" {
		return nil, fmt.Errorf("secret is required")
	}
	return &c, nil
}
