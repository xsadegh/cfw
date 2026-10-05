package main

import (
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

type reservedFlag []int

func (r *reservedFlag) String() string {
	parts := make([]string, len(*r))
	for i, v := range *r {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ",")
}

func (r *reservedFlag) Set(s string) error {
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.Atoi(p)
		if err != nil {
			return fmt.Errorf("invalid reserved byte %q", p)
		}
		if v < 0 || v > 255 {
			return fmt.Errorf("reserved byte %d out of range 0-255", v)
		}
		*r = append(*r, v)
	}
	return nil
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("cfw: ")

	var iface, listen, target string
	var reserved reservedFlag
	var jc, jMin, jMax int

	flag.StringVar(&iface, "interface", "", "egress network interface")
	flag.StringVar(&iface, "i", "", "shorthand for --interface")
	flag.StringVar(&listen, "listen", "", "relay mode: local ip:port for the WireGuard Endpoint (junk only, no eBPF)")
	flag.StringVar(&listen, "l", "", "shorthand for --listen")
	flag.StringVar(&target, "target", "", "wireguard endpoint as ip:port (required)")
	flag.StringVar(&target, "t", "", "shorthand for --target")
	flag.Var(&reserved, "reserved", "reserved bytes '100,178,104'")
	flag.Var(&reserved, "r", "shorthand for --reserved")
	flag.IntVar(&jc, "jc", 0, "junk packets before each handshake (0 = disabled)")
	flag.IntVar(&jMin, "jmin", 40, "minimum junk packet size (bytes)")
	flag.IntVar(&jMax, "jmax", 70, "maximum junk packet size (bytes)")

	flag.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, "usage: cfw -i <iface> -t <ip:port> [-r a,b,c] [--jc N --jmin N --jmax N]\n")
		_, _ = fmt.Fprint(os.Stderr, "       cfw -l <ip:port> -t <ip:port> --jc N [--jmin N --jmax N]\n\n")
		_, _ = fmt.Fprint(os.Stderr, "  reserved only: cfw -i eth0 -t 162.159.192.1:2408 -r 100,178,104\n")
		_, _ = fmt.Fprint(os.Stderr, "  junk only:     cfw -i eth0 -t 162.159.192.1:2408 --jc 4 --jmin 40 --jmax 70\n")
		_, _ = fmt.Fprint(os.Stderr, "  both:          cfw -i eth0 -t 162.159.192.1:2408 -r 100,178,104 --jc 4 --jmin 40 --jmax 70\n")
		_, _ = fmt.Fprint(os.Stderr, "  relay (macOS): cfw -l 127.0.0.1:51821 -t 162.159.192.1:2408 --jc 4 --jmin 40 --jmax 70\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if iface == "" && listen == "" {
		fatalUsage("missing required --interface/-i (or --listen/-l for relay mode)")
	}
	if iface != "" && listen != "" {
		fatalUsage("use either --interface/-i or --listen/-l, not both")
	}
	if target == "" {
		fatalUsage("missing required --target/-t")
	}

	addrPort, err := netip.ParseAddrPort(target)
	if err != nil {
		fatalUsage(fmt.Sprintf("invalid --target %q: %v", target, err))
	}
	addr := addrPort.Addr().Unmap()
	if !addr.Is4() {
		fatalUsage(fmt.Sprintf("--target %q must be IPv4", target))
	}
	addrPort = netip.AddrPortFrom(addr, addrPort.Port())

	var rb *[3]byte
	if len(reserved) > 0 {
		if len(reserved) != 3 {
			fatalUsage(fmt.Sprintf("--reserved needs exactly 3 bytes, got %d", len(reserved)))
		}
		rb = &[3]byte{byte(reserved[0]), byte(reserved[1]), byte(reserved[2])}
	}

	var junk *junkConfig
	if jc > 0 {
		if jMin <= 0 || jMax < jMin {
			fatalUsage("need 0 < --jmin <= --jmax")
		}
		junk = &junkConfig{count: jc, min: jMin, max: jMax}
	}

	if listen != "" {
		if rb != nil {
			fatalUsage("--reserved is not supported with --listen")
		}
		if junk == nil {
			fatalUsage("--listen needs --jc")
		}
		listenAddr, err := netip.ParseAddrPort(listen)
		if err != nil {
			fatalUsage(fmt.Sprintf("invalid --listen %q: %v", listen, err))
		}
		if err = runRelay(listenAddr, addrPort, *junk); err != nil {
			log.Fatal(err)
		}
		return
	}

	if rb == nil && junk == nil {
		fatalUsage("nothing to do: set -r (reserved) and/or --jc (junk)")
	}

	if err = run(iface, addrPort, rb, junk); err != nil {
		log.Fatal(err)
	}
}

func fatalUsage(msg string) {
	_, _ = fmt.Fprintf(os.Stderr, "cfw: %s\n\n", msg)
	flag.Usage()
	os.Exit(2)
}
