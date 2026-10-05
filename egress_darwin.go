//go:build darwin

package main

import (
	"net"
	"strings"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// egressInterface returns the physical interface that carries the IPv4
// default route. A full-tunnel WireGuard config also routes the target
// through its utun device, so the relay pins its upstream socket here.
// Otherwise the tunnel's own packets go back into the tunnel.
func egressInterface() (int, string) {
	rib, err := route.FetchRIB(unix.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return 0, ""
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return 0, ""
	}

	// While a VPN owns the default route, the physical default stays as a
	// scoped (RTF_IFSCOPE) route. Prefer the unscoped one, else the first
	// scoped one.
	var scoped *net.Interface
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&unix.RTF_UP == 0 || !isDefaultRoute(rm) {
			continue
		}
		ifi, err := net.InterfaceByIndex(rm.Index)
		if err != nil || ifi.Flags&net.FlagUp == 0 || isTunnel(ifi.Name) {
			continue
		}
		if rm.Flags&unix.RTF_IFSCOPE == 0 {
			return ifi.Index, ifi.Name
		}
		if scoped == nil {
			scoped = ifi
		}
	}
	if scoped != nil {
		return scoped.Index, scoped.Name
	}
	return 0, ""
}

func isDefaultRoute(rm *route.RouteMessage) bool {
	if rm.Flags&unix.RTF_HOST != 0 || len(rm.Addrs) <= unix.RTAX_NETMASK {
		return false
	}
	dst, ok := rm.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
	if !ok || dst.IP != [4]byte{} {
		return false
	}
	mask, ok := rm.Addrs[unix.RTAX_NETMASK].(*route.Inet4Addr)
	return !ok || mask.IP == [4]byte{}
}

func isTunnel(name string) bool {
	return strings.HasPrefix(name, "utun") || strings.HasPrefix(name, "ipsec")
}

func bindEgress(c syscall.RawConn, index int) error {
	if index == 0 {
		return nil
	}
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, index)
	})
	if err != nil {
		return err
	}
	return serr
}
