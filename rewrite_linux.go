//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	egressName  = "cfw_egress"
	ingressName = "cfw_ingress"
)

func run(iface string, target netip.AddrPort, reserved *[3]byte, junk *junkConfig) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock limit: %w", err)
	}

	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("lookup interface %s: %w", iface, err)
	}
	if err := ensureClsact(link); err != nil {
		return err
	}

	var junkMap *ebpf.Map
	if junk != nil {
		junkMap, err = ebpf.NewMap(&ebpf.MapSpec{
			Name:       "cfw_junk_rb",
			Type:       ebpf.RingBuf,
			MaxEntries: 1 << 16, // 64 KiB ring
		})
		if err != nil {
			return fmt.Errorf("create junk ring buffer: %w", err)
		}
	}

	var programs []*ebpf.Program
	var filters []*netlink.BpfFilter
	cleanup := func() {
		for _, filter := range filters {
			if err = netlink.FilterDel(filter); err != nil && !errors.Is(err, unix.ENOENT) {
				log.Printf("delete %s filter: %v", filter.Name, err)
			}
		}
		for _, program := range programs {
			_ = program.Close()
		}
		if junkMap != nil {
			_ = junkMap.Close()
		}
	}

	attachments := []struct {
		name    string
		parent  uint32
		dir     direction
		junkMap *ebpf.Map
	}{
		{egressName, netlink.HANDLE_MIN_EGRESS, dirEgress, junkMap},
	}
	if reserved != nil {
		attachments = append(attachments, struct {
			name    string
			parent  uint32
			dir     direction
			junkMap *ebpf.Map
		}{ingressName, netlink.HANDLE_MIN_INGRESS, dirIngress, nil})
	}

	for _, a := range attachments {
		deleteStaleFilters(link, a.parent, a.name)

		program, err := ebpf.NewProgram(&ebpf.ProgramSpec{
			Name:         a.name,
			Type:         ebpf.SchedCLS,
			License:      "GPL",
			Instructions: buildProgram(a.dir, target, reserved, a.junkMap),
		})
		if err != nil {
			cleanup()
			return fmt.Errorf("load %s program: %w", a.name, err)
		}

		filter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    a.parent,
				Handle:    netlink.MakeHandle(0, 1),
				Protocol:  unix.ETH_P_ALL,
				Priority:  1,
			},
			Fd:           program.FD(),
			Name:         a.name,
			DirectAction: true,
		}
		if err := netlink.FilterAdd(filter); err != nil {
			_ = program.Close()
			cleanup()
			return fmt.Errorf("attach %s filter to %s: %w", a.name, iface, err)
		}

		programs = append(programs, program)
		filters = append(filters, filter)
	}

	var stopSidecar func()
	if junk != nil {
		stopSidecar, err = startSidecar(junkMap, target, *junk)
		if err != nil {
			cleanup()
			return err
		}
	}

	log.Printf("attached to %s, target=%s, reserved=%v, junk=%v", iface, target, reserved != nil, junk != nil)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Printf("detaching")
	if stopSidecar != nil {
		stopSidecar()
	}
	cleanup()
	return nil
}

func ensureClsact(link netlink.Link) error {
	qdisc := &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
	}
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add clsact qdisc to %s: %w", link.Attrs().Name, err)
	}
	return nil
}

func deleteStaleFilters(link netlink.Link, parent uint32, name string) {
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return
	}
	for _, filter := range filters {
		if bpf, ok := filter.(*netlink.BpfFilter); ok && bpf.Name == name {
			_ = netlink.FilterDel(bpf)
		}
	}
}

type direction int

const (
	dirEgress direction = iota
	dirIngress
)

func buildProgram(dir direction, target netip.AddrPort, reserved *[3]byte, junkMap *ebpf.Map) asm.Instructions {
	const (
		tcActOK      = 0
		tcActShot    = 2
		ethPIP       = 0x0800
		ethHeaderLen = 14
		ipProtoUDP   = 17
		payloadCap   = 148 // WireGuard handshake initiation size
		eventSize    = 2 + payloadCap
	)

	ip4 := target.Addr().As4()
	ipImm := int64(binary.LittleEndian.Uint32(ip4[:]))
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], target.Port())
	portImm := int64(binary.LittleEndian.Uint16(portBytes[:]))

	var ipFieldOff, portFieldOff int32
	if dir == dirEgress {
		ipFieldOff, portFieldOff = 16, 2
	} else {
		ipFieldOff, portFieldOff = 12, 0
	}

	var w0, w1, w2, newLow int64
	if reserved != nil && dir == dirEgress {
		w0, w1, w2 = int64(reserved[0]), int64(reserved[1]), int64(reserved[2])
		newLow = int64(reserved[0])<<16 | int64(reserved[1])<<8 | int64(reserved[2])
	}

	emitLoad := func(base asm.Register, add int32, dst int16, size int32) asm.Instructions {
		return asm.Instructions{
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.Mov.Reg(asm.R2, base),
			asm.Add.Imm(asm.R2, add),
			asm.Mov.Reg(asm.R3, asm.RFP),
			asm.Add.Imm(asm.R3, int32(dst)),
			asm.Mov.Imm(asm.R4, size),
			asm.FnSkbLoadBytes.Call(),
			asm.JSLT.Imm(asm.R0, 0, "pass"),
		}
	}

	ins := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
	}

	if junkMap != nil {
		ins = append(ins,
			asm.LoadMem(asm.R1, asm.R6, 8, asm.Word),
			asm.JEq.Imm(asm.R1, int32(skbMark), "pass"),
		)
	}

	ins = append(ins,
		asm.LoadAbs(0, asm.Byte),
		asm.Mov.Reg(asm.R1, asm.R0),
		asm.RSh.Imm(asm.R1, 4),
		asm.JEq.Imm(asm.R1, 4, "raw_ip"),
		asm.JEq.Imm(asm.R1, 6, "pass"),
		asm.LoadAbs(12, asm.Half),
		asm.JEq.Imm(asm.R0, ethPIP, "eth_ip"),
		asm.Ja.Label("pass"),

		asm.Mov.Imm(asm.R7, 0).WithSymbol("raw_ip"),
		asm.Ja.Label("have_l3"),
		asm.Mov.Imm(asm.R7, ethHeaderLen).WithSymbol("eth_ip"),
	)

	proto := emitLoad(asm.R7, 9, -8, 1)
	proto[0] = proto[0].WithSymbol("have_l3")
	ins = append(ins, proto...)
	ins = append(ins,
		asm.LoadMem(asm.R1, asm.RFP, -8, asm.Byte),
		asm.JNE.Imm(asm.R1, ipProtoUDP, "pass"),
	)

	ins = append(ins, emitLoad(asm.R7, 0, -8, 1)...)
	ins = append(ins,
		asm.LoadMem(asm.R1, asm.RFP, -8, asm.Byte),
		asm.And.Imm(asm.R1, 0x0f),
		asm.LSh.Imm(asm.R1, 2),
		asm.Mov.Reg(asm.R8, asm.R7),
		asm.Add.Reg(asm.R8, asm.R1),
	)

	ins = append(ins, emitLoad(asm.R7, ipFieldOff, -8, 4)...)
	ins = append(ins,
		asm.LoadMem(asm.R1, asm.RFP, -8, asm.Word),
		asm.LoadImm(asm.R2, ipImm, asm.DWord),
		asm.JNE.Reg(asm.R1, asm.R2, "pass"),
	)

	ins = append(ins, emitLoad(asm.R8, portFieldOff, -8, 2)...)
	ins = append(ins,
		asm.LoadMem(asm.R1, asm.RFP, -8, asm.Half),
		asm.JNE.Imm(asm.R1, int32(portImm), "pass"),
	)

	ins = append(ins,
		asm.Mov.Reg(asm.R9, asm.R8),
		asm.Add.Imm(asm.R9, 8),
	)

	ins = append(ins, emitLoad(asm.R9, 0, -8, 4)...)

	if reserved != nil {
		ins = append(ins, emitLoad(asm.R8, 6, -16, 2)...)
		ins = append(ins,
			asm.LoadMem(asm.R1, asm.RFP, -16, asm.Half),
			asm.JEq.Imm(asm.R1, 0, "store"),

			asm.LoadMem(asm.R7, asm.RFP, -8, asm.Byte),
			asm.Mov.Reg(asm.R0, asm.R7),
			asm.LSh.Imm(asm.R0, 24),
			asm.LoadMem(asm.R3, asm.RFP, -7, asm.Byte),
			asm.LSh.Imm(asm.R3, 16),
			asm.LoadMem(asm.R1, asm.RFP, -6, asm.Byte),
			asm.LSh.Imm(asm.R1, 8),
			asm.Or.Reg(asm.R3, asm.R1),
			asm.LoadMem(asm.R1, asm.RFP, -5, asm.Byte),
			asm.Or.Reg(asm.R3, asm.R1),
			asm.Or.Reg(asm.R3, asm.R0),

			asm.Mov.Reg(asm.R4, asm.R0),
		)
		if newLow != 0 {
			ins = append(ins, asm.Or.Imm(asm.R4, int32(newLow)))
		}
		ins = append(ins,
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.Mov.Reg(asm.R2, asm.R8),
			asm.Add.Imm(asm.R2, 6),
			asm.Mov.Imm(asm.R5, 4),
			asm.FnL4CsumReplace.Call(),

			asm.StoreImm(asm.RFP, -16, w0, asm.Byte).WithSymbol("store"),
			asm.StoreImm(asm.RFP, -15, w1, asm.Byte),
			asm.StoreImm(asm.RFP, -14, w2, asm.Byte),
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.Mov.Reg(asm.R2, asm.R9),
			asm.Add.Imm(asm.R2, 1),
			asm.Mov.Reg(asm.R3, asm.RFP),
			asm.Add.Imm(asm.R3, -16),
			asm.Mov.Imm(asm.R4, 3),
			asm.Mov.Imm(asm.R5, 0),
			asm.FnSkbStoreBytes.Call(),
		)
	}

	if dir == dirEgress && junkMap != nil {
		ins = append(ins,
			asm.LoadMem(asm.R1, asm.RFP, -8, asm.Byte), // type
			asm.JNE.Imm(asm.R1, 1, "pass"),

			asm.LoadMapPtr(asm.R1, junkMap.FD()),
			asm.Mov.Imm(asm.R2, eventSize),
			asm.Mov.Imm(asm.R3, 0),
			asm.FnRingbufReserve.Call(),
			asm.JEq.Imm(asm.R0, 0, "pass"),
			asm.Mov.Reg(asm.R7, asm.R0),

			asm.Mov.Reg(asm.R1, asm.R6),
			asm.Mov.Reg(asm.R2, asm.R8),
			asm.Mov.Reg(asm.R3, asm.R7),
			asm.Mov.Imm(asm.R4, 2),
			asm.FnSkbLoadBytes.Call(),
			asm.JSLT.Imm(asm.R0, 0, "discard"),

			asm.Mov.Reg(asm.R1, asm.R6),
			asm.Mov.Reg(asm.R2, asm.R9),
			asm.Mov.Reg(asm.R3, asm.R7),
			asm.Add.Imm(asm.R3, 2),
			asm.Mov.Imm(asm.R4, payloadCap),
			asm.FnSkbLoadBytes.Call(),
			asm.JSLT.Imm(asm.R0, 0, "discard"),

			asm.Mov.Reg(asm.R1, asm.R7),
			asm.Mov.Imm(asm.R2, 0),
			asm.FnRingbufSubmit.Call(),
			asm.Mov.Imm(asm.R0, tcActShot),
			asm.Return(),

			asm.Mov.Reg(asm.R1, asm.R7).WithSymbol("discard"),
			asm.Mov.Imm(asm.R2, 0),
			asm.FnRingbufDiscard.Call(),
			asm.Ja.Label("pass"),
		)
	}

	ins = append(ins,
		asm.Mov.Imm(asm.R0, tcActOK).WithSymbol("pass"),
		asm.Return(),
	)

	return ins
}
