/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func TestRustBpfLoaderOptInDisabled(t *testing.T) {
	out, used, err := RustBpfLoaderOptInContract()
	if err != nil {
		t.Fatalf("RustBpfLoaderOptInContract() error = %v", err)
	}
	if used || out != "" {
		t.Fatalf("contract used helper while disabled: used=%v out=%q", used, out)
	}
}

func TestRustBpfLoaderOptInContractHelperSuccess(t *testing.T) {
	helper := writeRustBpfLoaderHelper(t, false)
	t.Setenv(rustBpfLoaderOptInEnv, "1")
	t.Setenv(rustBpfLoaderHelperEnv, helper)

	contract, used, err := RustBpfLoaderOptInContract()
	if err != nil {
		t.Fatalf("RustBpfLoaderOptInContract() error = %v", err)
	}
	if !used || !strings.Contains(contract, `"go_bpf_loader_removed_when_opted_in":true`) {
		t.Fatalf("unexpected contract output: used=%v out=%q", used, contract)
	}
}

func TestRustBpfLoaderOptInContractHelperFailure(t *testing.T) {
	helper := writeRustBpfLoaderHelper(t, true)
	t.Setenv(rustBpfLoaderOptInEnv, "1")
	t.Setenv(rustBpfLoaderHelperEnv, helper)

	_, used, err := RustBpfLoaderOptInContract()
	if !used {
		t.Fatalf("expected helper to be used")
	}
	if err == nil || !strings.Contains(err.Error(), "rust bpf loader helper failed: helper failed") {
		t.Fatalf("RustBpfLoaderOptInContract() error = %v", err)
	}
}

func BenchmarkRustBpfLoaderOptInContractHelper(b *testing.B) {
	helper := strings.TrimSpace(os.Getenv(rustBpfLoaderHelperEnv))
	if helper == "" {
		b.Skipf("%s is not set", rustBpfLoaderHelperEnv)
	}
	b.Setenv(rustBpfLoaderOptInEnv, "1")
	b.Setenv(rustBpfLoaderHelperEnv, helper)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out, used, err := RustBpfLoaderOptInContract()
		if err != nil {
			b.Fatal(err)
		}
		if !used || !strings.Contains(out, `"go_bpf_loader_removed_when_opted_in":true`) {
			b.Fatalf("unexpected helper output: used=%v out=%q", used, out)
		}
	}
}

func TestRustBpfLoaderOptInAdoptsPinnedObjectsAndUpdatesControlMaps(t *testing.T) {
	if os.Getenv("DAE_RUN_RUST_BPF_LOADER_CONTROL_PLANE_SMOKE") != "1" {
		t.Skip("set DAE_RUN_RUST_BPF_LOADER_CONTROL_PLANE_SMOKE=1 to run the root/BPF control-plane adoption smoke")
	}
	if os.Geteuid() != 0 {
		t.Skip("Rust/Aya BPF loader control-plane smoke requires root")
	}
	helper := strings.TrimSpace(os.Getenv(rustBpfLoaderHelperEnv))
	if helper == "" {
		t.Skipf("%s is not set", rustBpfLoaderHelperEnv)
	}
	if strings.ContainsRune(helper, os.PathSeparator) {
		if _, err := os.Stat(helper); err != nil {
			t.Fatalf("%s=%q is not usable: %v", rustBpfLoaderHelperEnv, helper, err)
		}
	} else if _, err := exec.LookPath(helper); err != nil {
		t.Fatalf("%s=%q is not in PATH: %v", rustBpfLoaderHelperEnv, helper, err)
	}

	ensureMemlock(t)
	pinPath, err := os.MkdirTemp("/sys/fs/bpf", "dae-rust-aya-loader-go-adopt-")
	if err != nil {
		t.Fatalf("MkdirTemp(/sys/fs/bpf): %v", err)
	}
	defer os.RemoveAll(pinPath)

	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	netns := testLoaderNetns(t)
	objs := new(bpfObjects)
	if err := fullLoadBpfObjectsViaRustAyaLoader(log, netns, objs, &loadBpfOptions{
		PinPath:             pinPath,
		HostTproxyPort:      12345,
		BigEndianTproxyPort: uint32(common.Htons(12345)),
		CollectionOptions: &ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{
				PinPath: pinPath,
			},
			Programs: ebpf.ProgramOptions{
				LogLevel:     ebpf.LogLevelBranch,
				LogSizeStart: 64 * 1024 * 10,
			},
		},
	}); err != nil {
		t.Fatalf("fullLoadBpfObjectsViaRustAyaLoader: %v", err)
	}

	core := newControlPlaneCore(log, objs, map[uint8]string{
		uint8(consts.OutboundDirect): consts.OutboundDirect.String(),
		uint8(consts.OutboundBlock):  consts.OutboundBlock.String(),
	}, nil, netns, false)
	defer func() {
		if err := core.Close(); err != nil {
			t.Fatalf("core.Close(): %v", err)
		}
	}()

	assertPinned := func(rel string) {
		t.Helper()
		if _, err := os.Stat(filepath.Join(pinPath, "rust_aya_loader", rel)); err != nil {
			t.Fatalf("expected Rust/Aya pinned object %s: %v", rel, err)
		}
	}
	assertPinned("maps/routing_map")
	assertPinned("maps/domain_routing_map")
	assertPinned("maps/outbound_connectivity_map")
	assertPinned("maps/listen_socket_map")
	assertPinned("programs/tproxy_dae0_ingress")

	builder, err := NewRoutingMatcherBuilder(
		log,
		nil,
		map[string]uint8{
			consts.OutboundDirect.String(): uint8(consts.OutboundDirect),
			consts.OutboundBlock.String():  uint8(consts.OutboundBlock),
		},
		objs,
		consts.OutboundDirect.String(),
	)
	if err != nil {
		t.Fatalf("NewRoutingMatcherBuilder: %v", err)
	}
	if err := builder.BuildKernspace(log); err != nil {
		t.Fatalf("BuildKernspace: %v", err)
	}
	var fallback bpfMatchSet
	if err := objs.RoutingMap.Lookup(uint32(0), &fallback); err != nil {
		t.Fatalf("RoutingMap fallback lookup: %v", err)
	}
	if fallback.Type != uint8(consts.MatchType_Fallback) ||
		fallback.Outbound != uint8(consts.OutboundDirect) {
		t.Fatalf("unexpected fallback route: type=%d outbound=%d", fallback.Type, fallback.Outbound)
	}

	cache := &DnsCache{
		DomainBitmap: domainRoutingBitmap(0x1),
		IPs:          []netip.Addr{netip.MustParseAddr("198.18.0.1")},
		HasAnyIP:     true,
	}
	if err := core.BatchUpdateDomainRouting(cache); err != nil {
		t.Fatalf("BatchUpdateDomainRouting: %v", err)
	}
	ip := netip.MustParseAddr("198.18.0.1").As16()
	var domainRouting bpfDomainRouting
	if err := objs.DomainRoutingMap.Lookup(common.Ipv6ByteSliceToUint32Array(ip[:]), &domainRouting); err != nil {
		t.Fatalf("DomainRoutingMap lookup: %v", err)
	}
	if domainRouting.Bitmap[0] != 0x1 {
		t.Fatalf("domain routing bitmap[0]=%#x, want 0x1", domainRouting.Bitmap[0])
	}

	core.outboundAliveChangeCallback(uint8(consts.OutboundDirect), false)(true, &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_4,
	}, true)
	var alive uint32
	if err := objs.OutboundConnectivityMap.Lookup(bpfOutboundConnectivityQuery{
		Outbound:  uint8(consts.OutboundDirect),
		L4proto:   consts.L4ProtoStr_TCP.ToL4Proto(),
		Ipversion: consts.IpVersionStr_4.ToIpVersion(),
	}, &alive); err != nil {
		t.Fatalf("OutboundConnectivityMap lookup: %v", err)
	}
	if alive != 1 {
		t.Fatalf("outbound connectivity alive=%d, want 1", alive)
	}

	listenConfig := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return dialer.TproxyControl(c)
		},
	}
	tcpRaw, err := listenConfig.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	tcpListener, ok := tcpRaw.(*net.TCPListener)
	if !ok {
		t.Fatalf("unexpected TCP listener type: %T", tcpRaw)
	}
	defer tcpListener.Close()
	udpRaw, err := listenConfig.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	udpConn, ok := udpRaw.(*net.UDPConn)
	if !ok {
		t.Fatalf("unexpected UDP listener type: %T", udpRaw)
	}
	defer udpConn.Close()
	if err := updateListenSocketMap(objs.ListenSocketMap, consts.ZeroKey, tcpListener); err != nil {
		t.Fatalf("update TCP listen socket map: %v", err)
	}
	if err := updateListenSocketMap(objs.ListenSocketMap, consts.OneKey, udpConn); err != nil {
		t.Fatalf("update UDP listen socket map: %v", err)
	}
}

func writeRustBpfLoaderHelper(t *testing.T, fail bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dae-daemon-optin")
	failBlock := ""
	if fail {
		failBlock = "echo helper failed\nexit 7\n"
	}
	script := "#!/bin/sh\nset -eu\n" + failBlock + `
if [ "$1" = "bpf-loader" ] && [ "$2" = "contract" ]; then
  printf '{"go_bpf_loader_removed_when_opted_in":true,"go_userspace_outbound_remains_authoritative":true}\n'
  exit 0
fi
echo unsupported command
exit 2
`
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	return path
}
