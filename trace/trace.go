/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package trace

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/daeuniverse/dae/common/consts"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	"github.com/sirupsen/logrus"
)

//go:generate go run -mod=mod github.com/cilium/ebpf/cmd/bpf2go -cc "$BPF_CLANG" "$BPF_STRIP_FLAG" -cflags "$BPF_CFLAGS" -target "$BPF_TRACE_TARGET" -type event bpf kern/trace.c -- -I./headers

var nativeEndian binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}

func StartTrace(ctx context.Context, ipVersion int, l4ProtoNo uint16, port int, dropOnly bool, outputFile string, ringbufSizeBytes uint32) (err error) {
	kernelVersion, err := internal.KernelVersion()
	if err != nil {
		return fmt.Errorf("failed to get kernel version: %w", err)
	}
	if requirement := consts.HelperBpfGetFuncIpVersionFeatureVersion; kernelVersion.Less(requirement) {
		return fmt.Errorf("your kernel version %v does not support bpf_get_func_ip; expect >=%v; upgrade your kernel and try again",
			kernelVersion.String(),
			requirement.String())
	}
	objs, err := rewriteAndLoadBpf(ipVersion, l4ProtoNo, port, ringbufSizeBytes)
	if err != nil {
		return
	}
	defer objs.Close()

	targets, kfreeSkbReasons, err := searchAvailableTargets()
	if err != nil {
		return
	}

	links, err := attachBpfToTargets(objs, targets)
	if err != nil {
		return
	}
	defer func() {
		i := 0
		fmt.Printf("\n")
		for _, link := range links {
			i++
			fmt.Printf("detaching kprobes: %04d/%04d\r", i, len(links))
			link.Close()
		}
		fmt.Printf("\n")
	}()

	fmt.Printf("\nstart tracing\n")
	if err = handleEvents(ctx, objs, outputFile, kfreeSkbReasons, dropOnly); err != nil {
		return
	}
	return
}

func rewriteAndLoadBpf(ipVersion int, l4ProtoNo uint16, port int, ringbufSizeBytes uint32) (_ *bpfObjects, err error) {
	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("failed to load BPF: %+v\n", err)
	}
	if err := spec.Variables["tracing_cfg"].Set(struct {
		port      uint16
		l4Proto   uint16
		ipVersion uint8
		pad       uint8
	}{
		port:      Htons(uint16(port)),
		l4Proto:   uint16(l4ProtoNo),
		ipVersion: uint8(ipVersion),
		pad:       0,
	}); err != nil {
		return nil, fmt.Errorf("failed to rewrite constants: %+v\n", err)
	}
	eventsSpec, ok := spec.Maps["events"]
	if !ok {
		return nil, fmt.Errorf("failed to find BPF map spec: events")
	}
	if ringbufSizeBytes == 0 {
		ringbufSizeBytes = DefaultRingbufSizeBytes()
	}
	eventsSpec.MaxEntries = ringbufSizeBytes
	var opts ebpf.CollectionOptions
	opts.Programs.LogLevel = ebpf.LogLevelInstruction
	opts.Programs.LogSizeStart = 64 * 1024 * 100
	objs := bpfObjects{}
	if err := spec.LoadAndAssign(&objs, &opts); err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}
		return nil, fmt.Errorf("failed to load BPF: %+v\n%s", err, verifierLog)
	}

	return &objs, nil
}

func searchAvailableTargets() (targets map[string]int, kfreeSkbReasons map[uint64]string, err error) {
	targets = map[string]int{}

	btfSpec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load kernel BTF: %+v\n", err)
	}

	if kfreeSkbReasons, err = getKFreeSKBReasons(btfSpec); err != nil {
		return
	}

	for typ, err := range btfSpec.All() {
		if err != nil {
			return nil, nil, fmt.Errorf("failed to iterate kernel BTF: %+v\n", err)
		}
		fn, ok := typ.(*btf.Func)
		if !ok {
			continue
		}

		fnName := string(fn.Name)

		fnProto := fn.Type.(*btf.FuncProto)
		i := 1
		for _, p := range fnProto.Params {
			if ptr, ok := p.Type.(*btf.Pointer); ok {
				if strct, ok := ptr.Target.(*btf.Struct); ok {
					if strct.Name == "sk_buff" && i <= 5 {
						name := fnName
						targets[name] = i
						continue
					}
				}
			}
			i += 1
		}
	}

	return targets, kfreeSkbReasons, nil
}

func getKFreeSKBReasons(spec *btf.Spec) (map[uint64]string, error) {
	if _, err := spec.AnyTypeByName("kfree_skb_reason"); err != nil {
		// Kernel is too old to have kfree_skb_reason
		return nil, nil
	}

	var dropReasonsEnum *btf.Enum
	if err := spec.TypeByName("skb_drop_reason", &dropReasonsEnum); err != nil {
		return nil, fmt.Errorf("failed to find 'skb_drop_reason' enum: %v", err)
	}

	ret := map[uint64]string{}
	for _, val := range dropReasonsEnum.Values {
		ret[uint64(val.Value)] = val.Name

	}

	return ret, nil
}

func attachBpfToTargets(objs *bpfObjects, targets map[string]int) (links []link.Link, err error) {
	kp, err := link.Kprobe("kfree_skbmem", objs.KprobeSkbLifetimeTermination, nil)
	if err != nil {
		logrus.Warnf("failed to attach kprobe to kfree_skbmem: %+v\n", err)
	} else {
		links = append(links, kp)
	}
	defer func() {
		if err != nil {
			for _, attached := range links {
				if attached != nil {
					_ = attached.Close()
				}
			}
			links = nil
		}
	}()

	i := 0
	attachedTargets := 0
	for fn, pos := range targets {
		i++
		fmt.Printf("attaching kprobes: %04d/%04d\r", i, len(targets))
		var kp link.Link
		switch pos {
		case 1:
			kp, err = link.Kprobe(fn, objs.KprobeSkb1, nil)
		case 2:
			kp, err = link.Kprobe(fn, objs.KprobeSkb2, nil)
		case 3:
			kp, err = link.Kprobe(fn, objs.KprobeSkb3, nil)
		case 4:
			kp, err = link.Kprobe(fn, objs.KprobeSkb4, nil)
		case 5:
			kp, err = link.Kprobe(fn, objs.KprobeSkb5, nil)
		default:
			logrus.Debugf("skip kprobe %s: unsupported skb arg position %d\n", fn, pos)
			continue
		}
		if err != nil {
			logrus.Debugf("failed to attach kprobe to %s: %+v\n", fn, err)
			continue
		}
		links = append(links, kp)
		attachedTargets++
	}
	if attachedTargets == 0 {
		err = fmt.Errorf("failed to attach kprobes to any target")
	}
	return links, err
}

func handleEvents(ctx context.Context, objs *bpfObjects, outputFile string, kfreeSkbReasons map[uint64]string, dropOnly bool) (err error) {
	writer, err := os.Create(outputFile)
	if err != nil {
		return
	}

	eventsReader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("failed to create ringbuf reader: %+v\n", err)
	}
	defer eventsReader.Close()

	go func() {
		<-ctx.Done()
		eventsReader.Close()
	}()

	tracker := newSkbTraceTracker()
	for {
		rec, err := eventsReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			logrus.Debugf("failed to read ringbuf: %+v", err)
			continue
		}

		var event traceEventRecord
		if err = binary.Read(bytes.NewBuffer(rec.RawSample), nativeEndian, &event); err != nil {
			logrus.Debugf("failed to parse ringbuf event: %+v", err)
			continue
		}

		sym := NearestSymbol(event.Pc)
		tracker.Add(event, sym.Name)
		switch sym.Name {
		case "__kfree_skb", "kfree_skbmem":
			// most skb end in the call of kfree_skbmem
			if !dropOnly || slices.Contains(tracker.SymNames(event.Skb), "kfree_skb_reason") {
				// trace dropOnly with drop reason or all skb
				for _, skb_ev := range tracker.Events(event.Skb) {
					fmt.Fprintf(writer, "%x mark=%x netns=%010d if=%d(%s) proc=%d(%s) ", skb_ev.Skb, skb_ev.Mark, skb_ev.Netns, skb_ev.Ifindex, TrimNull(string(skb_ev.Ifname[:])), skb_ev.Pid, TrimNull(string(skb_ev.Pname[:])))
					if event.L3Proto == syscall.ETH_P_IP {
						fmt.Fprintf(writer, "%s:%d > %s:%d ", net.IP(skb_ev.Saddr[:4]).String(), Ntohs(skb_ev.Sport), net.IP(skb_ev.Daddr[:4]).String(), Ntohs(skb_ev.Dport))
					} else {
						fmt.Fprintf(writer, "[%s]:%d > [%s]:%d ", net.IP(skb_ev.Saddr[:]).String(), Ntohs(skb_ev.Sport), net.IP(skb_ev.Daddr[:]).String(), Ntohs(skb_ev.Dport))
					}
					if event.L4Proto == syscall.IPPROTO_TCP {
						fmt.Fprintf(writer, "tcp_flags=%s ", TcpFlags(skb_ev.TcpFlags))
					}
					fmt.Fprintf(writer, "payload_len=%d ", event.PayloadLen)
					sym := NearestSymbol(skb_ev.Pc)
					fmt.Fprintf(writer, "%s", sym.Name)
					if sym.Name == "kfree_skb_reason" {
						fmt.Fprintf(writer, "(%s)", kfreeSkbReasons[skb_ev.SecondParam])
					}
					fmt.Fprintf(writer, "\n")
				}
				tracker.Delete(event.Skb)
			}
		}
	}
}
