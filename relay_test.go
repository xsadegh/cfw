package main

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestRelaySendsJunkBeforeHandshakeInit(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	junk := junkConfig{count: 3, min: 40, max: 70}
	r, err := newRelay(netip.MustParseAddrPort("127.0.0.1:0"), server.LocalAddr().(*net.UDPAddr).AddrPort(), junk)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()

	client, err := net.DialUDP("udp4", nil, r.local.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	initMsg := make([]byte, wgHandshakeInitLen)
	initMsg[0] = wgHandshakeInitType
	dataMsg := []byte{4, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef}
	for _, m := range [][]byte{initMsg, dataMsg} {
		if _, err = client.Write(m); err != nil {
			t.Fatal(err)
		}
	}

	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	read := func() ([]byte, netip.AddrPort) {
		t.Helper()
		n, from, err := server.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatal(err)
		}
		return buf[:n], from
	}

	for i := range junk.count {
		if b, _ := read(); len(b) < junk.min || len(b) > junk.max {
			t.Fatalf("junk %d: got %d bytes, want %d-%d", i, len(b), junk.min, junk.max)
		}
	}
	if b, _ := read(); !bytes.Equal(b, initMsg) {
		t.Fatalf("want handshake init after junk, got %d bytes", len(b))
	}
	b, relayAddr := read()
	if !bytes.Equal(b, dataMsg) {
		t.Fatalf("want data packet unchanged, got %x", b)
	}

	reply := []byte{2, 0, 0, 0, 1, 2, 3}
	if _, err = server.WriteToUDPAddrPort(reply, relayAddr); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], reply) {
		t.Fatalf("want reply relayed to client, got %x", buf[:n])
	}
}
