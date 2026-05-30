/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func TestRustBpfLoaderContractHelperSuccess(t *testing.T) {
	helper := writeRustBpfLoaderHelper(t, false)
	t.Setenv(rustBpfLoaderHelperEnv, helper)

	contract, err := RustBpfLoaderContract()
	if err != nil {
		t.Fatalf("RustBpfLoaderContract() error = %v", err)
	}
	if !strings.Contains(contract, `"go_bpf_loader_removed_when_opted_in":true`) {
		t.Fatalf("unexpected contract output: %q", contract)
	}
}

func TestRustBpfLoaderContractHelperFailure(t *testing.T) {
	helper := writeRustBpfLoaderHelper(t, true)
	t.Setenv(rustBpfLoaderHelperEnv, helper)

	_, err := RustBpfLoaderContract()
	if err == nil || !strings.Contains(err.Error(), "failed: helper failed") {
		t.Fatalf("RustBpfLoaderContract() error = %v", err)
	}
}

func TestRustBpfLoaderCommandContextUsesExplicitEnv(t *testing.T) {
	helper := writeRustBpfLoaderHelper(t, false)
	t.Setenv(rustBpfLoaderHelperEnv, helper)

	cmd, err := rustBpfLoaderCommandContext(context.Background(), "bpf-loader", "contract")
	if err != nil {
		t.Fatalf("rustBpfLoaderCommandContext() error = %v", err)
	}
	if cmd.Path != helper {
		t.Fatalf("helper path = %q, want %q", cmd.Path, helper)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper command failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if !strings.Contains(string(out), `"go_bpf_loader_removed_when_opted_in":true`) {
		t.Fatalf("unexpected helper output: %q", string(out))
	}
}

func TestRustAyaProductCallersUseExecutableResolver(t *testing.T) {
	for _, file := range []string{
		"rust_tproxy_listener.go",
		"rust_domain_routing_helper.go",
	} {
		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if strings.Contains(string(content), "rustBpfLoaderHelperPath(") {
			t.Fatalf("%s bypasses embedded loader resolution", file)
		}
	}
}

func TestRustAyaCgroupMonitorPinPaths(t *testing.T) {
	base := filepath.Join(t.TempDir(), "bpffs", consts.AppName)
	loaderRoot := rustAyaLoaderPinRoot(base)
	if loaderRoot != filepath.Join(base, rustAyaLoaderPinDirName) {
		t.Fatalf("loader root = %q", loaderRoot)
	}
	linkRoot := rustAyaCgroupLinkRoot(loaderRoot, 123, time.Unix(0, 456))
	want := filepath.Join(loaderRoot, "cgroup_links", "cp_123_456")
	if linkRoot != want {
		t.Fatalf("link root = %q, want %q", linkRoot, want)
	}
}

func BenchmarkRustBpfLoaderContractHelper(b *testing.B) {
	helper := strings.TrimSpace(os.Getenv(rustBpfLoaderHelperEnv))
	if helper == "" {
		b.Skipf("%s is not set", rustBpfLoaderHelperEnv)
	}
	b.Setenv(rustBpfLoaderHelperEnv, helper)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out, err := RustBpfLoaderContract()
		if err != nil {
			b.Fatal(err)
		}
		if !strings.Contains(out, `"go_bpf_loader_removed_when_opted_in":true`) {
			b.Fatalf("unexpected helper output: %q", out)
		}
	}
}

func TestRustBpfLoaderAdoptsPinnedObjectsAndUpdatesControlMaps(t *testing.T) {
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
		PinPath:        pinPath,
		HostTproxyPort: 12345,
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
	assertRustCgroupMonitorAttachPin(t, pinPath)

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

	lpmBuilder, err := NewRoutingMatcherBuilder(
		log,
		[]*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_Ip,
				Params: []*config_parser.Param{{
					Val: "203.0.113.0/24",
				}},
			}},
			Outbound: config_parser.Function{Name: consts.OutboundBlock.String()},
		}},
		map[string]uint8{
			consts.OutboundDirect.String(): uint8(consts.OutboundDirect),
			consts.OutboundBlock.String():  uint8(consts.OutboundBlock),
		},
		objs,
		consts.OutboundDirect.String(),
	)
	if err != nil {
		t.Fatalf("NewRoutingMatcherBuilder with IP rule: %v", err)
	}
	if err := lpmBuilder.updateKernelRoutingMapsViaRustHelper(); err != nil {
		t.Fatalf("updateKernelRoutingMapsViaRustHelper with LPM rule: %v", err)
	}
	var ipRule bpfMatchSet
	if err := objs.RoutingMap.Lookup(uint32(0), &ipRule); err != nil {
		t.Fatalf("RoutingMap IP rule lookup: %v", err)
	}
	if ipRule.Type != uint8(consts.MatchType_IpSet) ||
		ipRule.Outbound != uint8(consts.OutboundBlock) {
		t.Fatalf("unexpected IP route: type=%d outbound=%d", ipRule.Type, ipRule.Outbound)
	}
	if err := objs.RoutingMap.Lookup(uint32(1), &fallback); err != nil {
		t.Fatalf("RoutingMap fallback after IP rule lookup: %v", err)
	}
	if fallback.Type != uint8(consts.MatchType_Fallback) ||
		fallback.Outbound != uint8(consts.OutboundDirect) {
		t.Fatalf("unexpected fallback after IP route: type=%d outbound=%d", fallback.Type, fallback.Outbound)
	}
	var inner *ebpf.Map
	if err := objs.LpmArrayMap.Lookup(uint32(0), &inner); err != nil {
		t.Fatalf("LpmArrayMap inner lookup: %v", err)
	}
	defer inner.Close()
	lpmLookupKey := cidrToBpfLpmKey(netip.MustParsePrefix("203.0.113.42/32"))
	var lpmValue uint32
	if err := inner.Lookup(lpmLookupKey, &lpmValue); err != nil {
		t.Fatalf("Rust-created LPM inner map lookup: %v", err)
	}
	if lpmValue != 1 {
		t.Fatalf("Rust-created LPM value=%d, want 1", lpmValue)
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

func assertRustCgroupMonitorAttachPin(t *testing.T, pinPath string) {
	t.Helper()
	cgroupRoot, err := detectCgroupPath()
	if err != nil {
		t.Skipf("skip Rust/Aya cgroup monitor attach smoke: %v", err)
	}
	cgroupPath := filepath.Join(cgroupRoot, fmt.Sprintf("dae-rust-cgroup-%d", os.Getpid()))
	_ = os.RemoveAll(cgroupPath)
	if err := os.Mkdir(cgroupPath, 0755); err != nil {
		t.Skipf("skip Rust/Aya cgroup monitor attach smoke: create %s: %v", cgroupPath, err)
	}
	defer os.RemoveAll(cgroupPath)

	linkRoot := filepath.Join(pinPath, rustAyaLoaderPinDirName, "cgroup_links", "test")
	_ = os.RemoveAll(linkRoot)
	defer os.RemoveAll(linkRoot)
	out, err := runRustBpfLoaderHelperOutput(
		"cgroup-monitor", "attach-pin",
		"--program-root", filepath.Join(pinPath, rustAyaLoaderPinDirName, "programs"),
		"--link-root", linkRoot,
		"--cgroup-path", cgroupPath,
	)
	if err != nil {
		t.Fatalf("cgroup-monitor attach-pin: %v", err)
	}
	if !strings.Contains(out, `"scope":"cgroup-pname-monitor-attach-pin"`) {
		t.Fatalf("unexpected cgroup monitor output: %s", out)
	}
	entries, err := os.ReadDir(linkRoot)
	if err != nil {
		t.Fatalf("read cgroup link root: %v", err)
	}
	if len(entries) != 6 {
		t.Fatalf("expected 6 pinned cgroup links, got %d", len(entries))
	}
}

func writeRustBpfLoaderHelper(t *testing.T, fail bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dae-aya-bpf-loader")
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
