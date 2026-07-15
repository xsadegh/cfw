//go:build linux

package main

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	sidecarPayloadCap = 148
	sidecarEventSize  = 2 + sidecarPayloadCap
)

func startSidecar(rb *ebpf.Map, target netip.AddrPort, junk junkConfig) (func(), error) {
	reader, err := ringbuf.NewReader(rb)
	if err != nil {
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		_ = reader.Close()
		return nil, fmt.Errorf("raw socket (need CAP_NET_RAW): %w", err)
	}

	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, skbMark); err != nil {
		_ = reader.Close()
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("set SO_MARK (need CAP_NET_ADMIN): %w", err)
	}

	srcIP, err := outboundIP(target)
	if err != nil {
		_ = reader.Close()
		_ = syscall.Close(fd)
		return nil, err
	}

	dstIP := target.Addr().As4()
	dstPort := target.Port()
	dst := &syscall.SockaddrInet4{Addr: dstIP}

	go func() {
		for {
			var rec ringbuf.Record
			rec, err = reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("ring buffer read: %v", err)
				continue
			}
			if len(rec.RawSample) < sidecarEventSize {
				continue
			}
			srcPort := binary.BigEndian.Uint16(rec.RawSample[0:2])
			initPayload := rec.RawSample[2 : 2+sidecarPayloadCap]

			for i := 0; i < junk.count; i++ {
				body := make([]byte, junkSize(junk.min, junk.max))
				_, _ = crand.Read(body)
				pkt := buildUDPDatagram(srcIP, dstIP, srcPort, dstPort, body)
				if err := syscall.Sendto(fd, pkt, 0, dst); err != nil {
					log.Printf("send junk: %v", err)
				}
			}

			pkt := buildUDPDatagram(srcIP, dstIP, srcPort, dstPort, initPayload)
			if err = syscall.Sendto(fd, pkt, 0, dst); err != nil {
				log.Printf("reinject handshake init: %v", err)
			}
		}
	}()

	stop := func() {
		_ = reader.Close()
		_ = syscall.Close(fd)
	}
	return stop, nil
}

func outboundIP(target netip.AddrPort) ([4]byte, error) {
	c, err := net.Dial("udp4", target.String())
	if err != nil {
		return [4]byte{}, fmt.Errorf("determine source ip toward %s: %w", target, err)
	}
	defer c.Close()

	local, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return [4]byte{}, fmt.Errorf("unexpected local address type %T", c.LocalAddr())
	}
	return local.AddrPort().Addr().Unmap().As4(), nil
}
