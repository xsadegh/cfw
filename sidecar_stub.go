//go:build !linux

package main

import (
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
)

func startSidecar(_ *ebpf.Map, _ netip.AddrPort, _ junkConfig) (func(), error) {
	return nil, fmt.Errorf("--interface requires linux (eBPF TC), use --listen for relay mode")
}
