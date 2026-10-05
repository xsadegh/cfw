package main

import (
	crand "crypto/rand"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	wgHandshakeInitType = 1
	wgHandshakeInitLen  = 148
	relaySocketBuffer   = 4 << 20
	relayRedialBackoff  = time.Second
)

// relay sits between one local WireGuard client and the target. WireGuard's
// Endpoint points at the relay's listen address. Every datagram is copied
// through unchanged; only a handshake initiation gets junk packets sent
// ahead of it.
type relay struct {
	target netip.AddrPort
	junk   junkConfig
	local  *net.UDPConn

	client atomic.Pointer[netip.AddrPort] // last WireGuard source address
	up     atomic.Pointer[net.UDPConn]    // connected socket to the target
	closed atomic.Bool

	// Owned by the toTarget goroutine after newRelay returns.
	egress   int
	dialedAt time.Time
}

func runRelay(listen, target netip.AddrPort, junk junkConfig) error {
	r, err := newRelay(listen, target, junk)
	if err != nil {
		return err
	}

	log.Printf("relaying %s -> %s, junk=%d (%d-%d bytes)", r.local.LocalAddr(), target, junk.count, junk.min, junk.max)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Printf("stopping")
	r.close()
	return nil
}

func newRelay(listen, target netip.AddrPort, junk junkConfig) (*relay, error) {
	local, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(listen))
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", listen, err)
	}
	_ = local.SetReadBuffer(relaySocketBuffer)
	_ = local.SetWriteBuffer(relaySocketBuffer)

	r := &relay{target: target, junk: junk, local: local}
	if _, err = r.redial(true); err != nil {
		_ = local.Close()
		return nil, err
	}

	go r.toTarget()
	go r.toClient()
	return r, nil
}

func (r *relay) close() {
	r.closed.Store(true)
	_ = r.local.Close()
	_ = r.up.Load().Close()
}

func (r *relay) toTarget() {
	buf := make([]byte, 1<<16)
	junk := make([]byte, r.junk.max)

	for {
		n, from, err := r.local.ReadFromUDPAddrPort(buf)
		if err != nil {
			if r.closed.Load() {
				return
			}
			log.Printf("read from client: %v", err)
			continue
		}
		if c := r.client.Load(); c == nil || *c != from {
			r.client.Store(&from)
			log.Printf("client %s", from)
		}

		pkt := buf[:n]
		up := r.up.Load()
		if isHandshakeInit(pkt) {
			// Handshakes are rare, so this is the cheap moment to follow a
			// network change (Wi-Fi to Ethernet, new DHCP lease).
			if c, err := r.redial(false); err == nil {
				up = c
			}
			for range r.junk.count {
				b := junk[:junkSize(r.junk.min, r.junk.max)]
				_, _ = crand.Read(b)
				_, _ = up.Write(b)
			}
		}

		if _, err = up.Write(pkt); err != nil && !errors.Is(err, syscall.ECONNREFUSED) {
			// The source address or interface went away under the socket.
			if time.Since(r.dialedAt) > relayRedialBackoff {
				_, _ = r.redial(true)
			}
		}
	}
}

func (r *relay) toClient() {
	buf := make([]byte, 1<<16)

	for {
		up := r.up.Load()
		n, err := up.Read(buf)
		if err != nil {
			if r.closed.Load() {
				return
			}
			// ErrClosed: a redial swapped the socket. ECONNREFUSED: an ICMP
			// error from the target. Both are expected.
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, syscall.ECONNREFUSED) {
				log.Printf("read from target: %v", err)
				time.Sleep(100 * time.Millisecond)
			}
			continue
		}
		if c := r.client.Load(); c != nil {
			_, _ = r.local.WriteToUDPAddrPort(buf[:n], *c)
		}
	}
}

// redial connects a new upstream socket, pinned to the current egress
// interface. Without force, it keeps the current socket when the egress
// interface did not change.
func (r *relay) redial(force bool) (*net.UDPConn, error) {
	index, name := 0, ""
	if !r.target.Addr().IsLoopback() {
		index, name = egressInterface()
	}

	old := r.up.Load()
	if old != nil && !force && index == r.egress {
		return old, nil
	}

	d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		return bindEgress(c, index)
	}}
	r.dialedAt = time.Now()
	conn, err := d.Dial("udp4", r.target.String())
	if err != nil {
		if old == nil {
			return nil, fmt.Errorf("dial %s: %w", r.target, err)
		}
		log.Printf("dial %s: %v", r.target, err)
		return old, err
	}
	up := conn.(*net.UDPConn)
	_ = up.SetReadBuffer(relaySocketBuffer)
	_ = up.SetWriteBuffer(relaySocketBuffer)

	if old == nil || index != r.egress {
		if name != "" {
			log.Printf("egress pinned to %s", name)
		} else {
			log.Printf("egress follows the routing table")
		}
	}
	r.egress = index
	r.up.Store(up)
	if old != nil {
		_ = old.Close()
	}
	return up, nil
}

func isHandshakeInit(b []byte) bool {
	return len(b) == wgHandshakeInitLen && b[0] == wgHandshakeInitType
}
