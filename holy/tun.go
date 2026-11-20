package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Linux TUN ioctl constants (arch-independent on linux/amd64 & arm64).
const (
	cTUNSETIFF = 0x400454ca
	cIFF_TUN   = 0x0001
	cIFF_NO_PI = 0x1000
)

// tunDevice wraps an open /dev/net/tun file descriptor.
type tunDevice struct {
	f    *os.File
	name string
}

// openTUN allocates (or attaches to) a layer-3 TUN interface with the given
// name and returns a handle for reading/writing raw IP packets.
func openTUN(name string) (*tunDevice, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	var req [40]byte
	copy(req[:15], []byte(name))
	flags := uint16(cIFF_TUN | cIFF_NO_PI)
	req[16] = byte(flags & 0xff)
	req[17] = byte(flags >> 8)

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(cTUNSETIFF),
		uintptr(unsafe.Pointer(&req[0])),
	)
	if errno != 0 {
		f.Close()
		return nil, fmt.Errorf("TUNSETIFF: %v", errno)
	}

	// Resolve the effective interface name returned by the kernel.
	end := 0
	for end < 16 && req[end] != 0 {
		end++
	}
	ifName := string(req[:end])

	return &tunDevice{f: f, name: ifName}, nil
}

func (t *tunDevice) Read(b []byte) (int, error)  { return t.f.Read(b) }
func (t *tunDevice) Write(b []byte) (int, error) { return t.f.Write(b) }
func (t *tunDevice) Close() error                { return t.f.Close() }
