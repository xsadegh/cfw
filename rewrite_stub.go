//go:build !linux

package main

import (
	"fmt"
	"net/netip"
)

func run(_ string, _ netip.AddrPort, _ *[3]byte, _ *junkConfig) error {
	return fmt.Errorf("--interface requires linux (eBPF TC), use --listen for relay mode")
}
