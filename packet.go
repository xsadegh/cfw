package main

import "encoding/binary"

const (
	ipHeaderLen  = 20
	udpHeaderLen = 8
)

func buildUDPDatagram(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	total := ipHeaderLen + udpHeaderLen + len(payload)
	pkt := make([]byte, total)

	// IPv4 header.
	pkt[0] = 0x45 // version 4, IHL 5 (20 bytes)
	binary.BigEndian.PutUint16(pkt[2:], uint16(total))
	pkt[8] = 64 // TTL
	pkt[9] = 17 // protocol UDP
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])
	binary.BigEndian.PutUint16(pkt[10:], internetChecksum(pkt[:ipHeaderLen]))

	// UDP header + payload.
	udp := pkt[ipHeaderLen:]
	binary.BigEndian.PutUint16(udp[0:], srcPort)
	binary.BigEndian.PutUint16(udp[2:], dstPort)
	binary.BigEndian.PutUint16(udp[4:], uint16(udpHeaderLen+len(payload)))
	copy(udp[udpHeaderLen:], payload)
	binary.BigEndian.PutUint16(udp[6:], udpChecksum(srcIP, dstIP, udp))

	return pkt
}

// internetChecksum computes the standard 16-bit one's-complement checksum.
func internetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// udpChecksum computes the UDP checksum over the IPv4 pseudo-header and the UDP
// header+payload (whose checksum field must currently be zero).
func udpChecksum(srcIP, dstIP [4]byte, udp []byte) uint16 {
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(srcIP[0:]))
	sum += uint32(binary.BigEndian.Uint16(srcIP[2:]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[0:]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[2:]))
	sum += uint32(17) // protocol
	sum += uint32(len(udp))
	for i := 0; i+1 < len(udp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udp[i:]))
	}
	if len(udp)%2 == 1 {
		sum += uint32(udp[len(udp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	cs := ^uint16(sum)
	if cs == 0 {
		cs = 0xffff // 0 means "no checksum" in UDP; send all-ones instead
	}
	return cs
}
