# cfw

Kernel WireGuard can't touch the transport-header "reserved" bytes or send junk
packets ahead of the handshake — but some WireGuard services expect that.
Cloudflare WARP, for example, uses the reserved bytes as a client id. `cfw`
adds both on top of stock kernel WireGuard, in-flight, with no proxy in the
data path and zero overhead.

- **Reserved-bytes rewrite** — an eBPF TC program stamps the 3 reserved bytes on
  egress to the endpoint and zeroes them on ingress, fixing up the UDP checksum
  in place. Runs at line rate; no userspace hop for normal traffic.
- **Junk packets** — eBPF detects the outgoing handshake initiation, drops it,
  and hands it to the sidecar. The sidecar sends N random-sized junk UDP packets
  to the endpoint first, then re-sends the real initiation via a raw socket with
  the WireGuard source port preserved, so the reply routes straight back to the kernel.

Either feature works alone or combined. Point your WireGuard peer's `Endpoint`
at the real remote as usual — `cfw` attaches to the primary interface.

## How it works

```
WireGuard  egress-->   [eBPF: stamp reserved]    --> NIC
WireGuard  <--ingress  [eBPF: zero reserved]     <-- NIC

Junk sidecar:
  handshake init  --> eBPF ring buffer --> sidecar --> N junk packets, then the init
```

The sidecar's packets are tagged with `SO_MARK` so the egress program passes
them straight through instead of re-capturing them (which would loop).

## Requirements

- Linux, `CAP_NET_ADMIN` + `CAP_BPF` (TC/eBPF attach), and `CAP_NET_RAW` if junk
  packets are enabled (raw socket). Easiest to just run as root.
- Relay mode (`-l`, for macOS) needs no special privileges.

## Build

```
go build -o cfw .
```

## Usage

```
cfw -i <iface> -t <ip:port> [-r a,b,c] [--jc N --jmin N --jmax N]
cfw -l <ip:port> -t <ip:port> --jc N [--jmin N --jmax N]
```

| Flag          | Shorthand | Description                                                              |
|---------------|-----------|--------------------------------------------------------------------------|
| `--interface` | `-i`      | Egress network interface (required, Linux only)                          |
| `--listen`    | `-l`      | Relay mode: local `ip:port` for the `Endpoint`, replaces `-i`            |
| `--target`    | `-t`      | WireGuard endpoint as `ip:port`, IPv4 only (required)                    |
| `--reserved`  | `-r`      | 3 reserved bytes, comma-separated, e.g. `100,178,104` (optional)         |
| `--jc`        |           | Junk packets to send before each handshake init (default `0` = disabled) |
| `--jmin`      |           | Minimum junk packet size in bytes (default `40`)                         |
| `--jmax`      |           | Maximum junk packet size in bytes (default `70`)                         |

At least one of `-r` or `--jc` must be set.

### Examples

Reserved bytes (e.g. Cloudflare's WARP):

```
sudo cfw -i eth0 -t 162.159.192.1:2408 -r 100,178,104
```

Junk packets (handshake obfuscation):

```
sudo cfw -i eth0 -t 162.159.192.1:2408 --jc 4 --jmin 40 --jmax 70
```

Point your WireGuard peer's `Endpoint` at the real target (`162.159.192.1:2408`
above). `cfw` does not proxy traffic through a local address; it rewrites it
on the interface you attach to.

## macOS (Relay mode)

macOS has no eBPF, so `cfw` runs as a local UDP relay there. Relay mode
supports junk packets only. The WireGuard `Endpoint` points at the relay, and
the relay forwards every packet to the target unchanged. Before each handshake
initiation, the relay sends `--jc` junk packets to the target.
