package control

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"unsafe"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	"github.com/sirupsen/logrus"
)

const controlGoldenUpdateEnv = "DAE_UPDATE_REBUILD_GOLDEN"

func TestWriteControlDatapathGoldenFixtures(t *testing.T) {
	writeOrCheckControlGolden(t, "../testdata/rebuild-golden/ebpf/abi/layout.json", rebuildGoldenStage7BpfAbiLayout())
	writeOrCheckControlGolden(t, "../testdata/rebuild-golden/ebpf/maps/catalog.json", rebuildGoldenStage7BpfMapCatalog(t))
	writeOrCheckControlGolden(t, "../testdata/rebuild-golden/ebpf/kernel_features/basic.json", rebuildGoldenStage7KernelFeatures())
	writeOrCheckControlGolden(t, "../testdata/rebuild-golden/control/domain_routing_tracker/basic.json", rebuildGoldenStage7DomainRoutingTracker(t))
	writeOrCheckControlGolden(t, "../testdata/rebuild-golden/control/reload_bpf_ownership/eject_inject.json", rebuildGoldenStage7ReloadBpfOwnership())
	writeOrCheckControlGolden(t, "../testdata/rebuild-golden/control/active_datapath/optin_contract.json", rebuildGoldenStage14ActiveDatapathOptInContract())
	writeOrCheckControlGolden(t, "../testdata/rebuild-golden/control/outbound_connectivity/dryrun.json", rebuildGoldenStage7OutboundConnectivity())
	writeOrCheckControlGolden(t, "../testdata/rebuild-golden/datapath/udp_pools/basic.json", rebuildGoldenStage7UdpPools())
	writeOrCheckControlGolden(t, "../testdata/rebuild-golden/datapath/route_loop/basic.json", rebuildGoldenStage7RouteLoop())
	writeOrCheckControlGolden(t, "../testdata/rebuild-golden/datapath/magic_network/mark_mptcp.json", rebuildGoldenStage7MagicNetwork())
}

func writeOrCheckControlGolden(t *testing.T, path string, value any) {
	t.Helper()

	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	data = append(data, '\n')

	if os.Getenv(controlGoldenUpdateEnv) == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !controlJsonEqual(want, data) {
		t.Fatalf("%s does not match generated golden; run %s=1 go test ./control -run TestWriteControlDatapathGoldenFixtures", path, controlGoldenUpdateEnv)
	}
}

func controlJsonEqual(a, b []byte) bool {
	var av any
	var bv any
	if err := json.Unmarshal(a, &av); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}

func rebuildGoldenStage7BpfAbiLayout() any {
	return map[string]any{
		"name": "stage7-bpf-abi-layout",
		"source": []string{
			"control/bpf_bpfel.go",
			"control/kern/tproxy.c",
			"common/consts/ebpf.go",
		},
		"task_comm_len": consts.TaskCommLen,
		"max_match_set_len": map[string]any{
			"value":        consts.MaxMatchSetLen,
			"bitmap_words": consts.MaxMatchSetLen / 32,
		},
		"structs": []map[string]any{
			structLayout("bpfDaeParam", bpfDaeParam{}, map[string]uintptr{
				"tproxy_port":              unsafe.Offsetof(bpfDaeParam{}.TproxyPort),
				"control_plane_pid":        unsafe.Offsetof(bpfDaeParam{}.ControlPlanePid),
				"dae0_ifindex":             unsafe.Offsetof(bpfDaeParam{}.Dae0Ifindex),
				"dae_netns_id":             unsafe.Offsetof(bpfDaeParam{}.DaeNetnsId),
				"dae0peer_mac":             unsafe.Offsetof(bpfDaeParam{}.Dae0peerMac),
				"has_bpf_get_current_task": unsafe.Offsetof(bpfDaeParam{}.HasBpfGetCurrentTask),
				"padding":                  unsafe.Offsetof(bpfDaeParam{}.Padding),
			}),
			structLayout("bpfDomainRouting", bpfDomainRouting{}, map[string]uintptr{
				"bitmap": unsafe.Offsetof(bpfDomainRouting{}.Bitmap),
			}),
			structLayout("bpfMatchSet", bpfMatchSet{}, map[string]uintptr{
				"value":    unsafe.Offsetof(bpfMatchSet{}.Value),
				"not":      unsafe.Offsetof(bpfMatchSet{}.Not),
				"type":     unsafe.Offsetof(bpfMatchSet{}.Type),
				"outbound": unsafe.Offsetof(bpfMatchSet{}.Outbound),
				"must":     unsafe.Offsetof(bpfMatchSet{}.Must),
				"mark":     unsafe.Offsetof(bpfMatchSet{}.Mark),
			}),
			structLayout("bpfOutboundConnectivityQuery", bpfOutboundConnectivityQuery{}, map[string]uintptr{
				"outbound":  unsafe.Offsetof(bpfOutboundConnectivityQuery{}.Outbound),
				"l4proto":   unsafe.Offsetof(bpfOutboundConnectivityQuery{}.L4proto),
				"ipversion": unsafe.Offsetof(bpfOutboundConnectivityQuery{}.Ipversion),
			}),
			structLayout("bpfPidPname", bpfPidPname{}, map[string]uintptr{
				"pid":   unsafe.Offsetof(bpfPidPname{}.Pid),
				"pname": unsafe.Offsetof(bpfPidPname{}.Pname),
			}),
			structLayout("bpfRedirectEntry", bpfRedirectEntry{}, map[string]uintptr{
				"ifindex":  unsafe.Offsetof(bpfRedirectEntry{}.Ifindex),
				"smac":     unsafe.Offsetof(bpfRedirectEntry{}.Smac),
				"dmac":     unsafe.Offsetof(bpfRedirectEntry{}.Dmac),
				"from_wan": unsafe.Offsetof(bpfRedirectEntry{}.FromWan),
			}),
			structLayout("bpfRedirectTuple", bpfRedirectTuple{}, map[string]uintptr{
				"sip": unsafe.Offsetof(bpfRedirectTuple{}.Sip),
				"dip": unsafe.Offsetof(bpfRedirectTuple{}.Dip),
			}),
			structLayout("bpfRoutingResult", bpfRoutingResult{}, map[string]uintptr{
				"mark":     unsafe.Offsetof(bpfRoutingResult{}.Mark),
				"must":     unsafe.Offsetof(bpfRoutingResult{}.Must),
				"mac":      unsafe.Offsetof(bpfRoutingResult{}.Mac),
				"outbound": unsafe.Offsetof(bpfRoutingResult{}.Outbound),
				"pname":    unsafe.Offsetof(bpfRoutingResult{}.Pname),
				"pid":      unsafe.Offsetof(bpfRoutingResult{}.Pid),
				"dscp":     unsafe.Offsetof(bpfRoutingResult{}.Dscp),
			}),
			structLayout("bpfTuplesKey", bpfTuplesKey{}, map[string]uintptr{
				"sip":     unsafe.Offsetof(bpfTuplesKey{}.Sip),
				"dip":     unsafe.Offsetof(bpfTuplesKey{}.Dip),
				"sport":   unsafe.Offsetof(bpfTuplesKey{}.Sport),
				"dport":   unsafe.Offsetof(bpfTuplesKey{}.Dport),
				"l4proto": unsafe.Offsetof(bpfTuplesKey{}.L4proto),
			}),
			structLayout("bpfUdpConnState", bpfUdpConnState{}, map[string]uintptr{
				"is_wan_ingress_direction": unsafe.Offsetof(bpfUdpConnState{}.IsWanIngressDirection),
				"timer":                    unsafe.Offsetof(bpfUdpConnState{}.Timer),
			}),
		},
		"match_type_order": []map[string]any{
			{"name": "DomainSet", "value": uint8(consts.MatchType_DomainSet)},
			{"name": "IpSet", "value": uint8(consts.MatchType_IpSet)},
			{"name": "SourceIpSet", "value": uint8(consts.MatchType_SourceIpSet)},
			{"name": "Port", "value": uint8(consts.MatchType_Port)},
			{"name": "SourcePort", "value": uint8(consts.MatchType_SourcePort)},
			{"name": "L4Proto", "value": uint8(consts.MatchType_L4Proto)},
			{"name": "IpVersion", "value": uint8(consts.MatchType_IpVersion)},
			{"name": "Mac", "value": uint8(consts.MatchType_Mac)},
			{"name": "ProcessName", "value": uint8(consts.MatchType_ProcessName)},
			{"name": "Dscp", "value": uint8(consts.MatchType_Dscp)},
			{"name": "Fallback", "value": uint8(consts.MatchType_Fallback)},
			{"name": "MustRules", "value": uint8(consts.MatchType_MustRules)},
			{"name": "Upstream", "value": uint8(consts.MatchType_Upstream)},
			{"name": "QType", "value": uint8(consts.MatchType_QType)},
		},
		"link_header_lengths": map[string]any{
			"none":     consts.LinkHdrLen_None,
			"ethernet": consts.LinkHdrLen_Ethernet,
		},
		"tproxy_mark": consts.TproxyMark,
	}
}

func structLayout[T any](name string, zero T, fields map[string]uintptr) map[string]any {
	offsets := make([]map[string]any, 0, len(fields))
	names := make([]string, 0, len(fields))
	for field := range fields {
		names = append(names, field)
	}
	sort.Strings(names)
	for _, field := range names {
		offsets = append(offsets, map[string]any{
			"field":  field,
			"offset": fields[field],
		})
	}
	return map[string]any{
		"name":    name,
		"size":    unsafe.Sizeof(zero),
		"align":   unsafe.Alignof(zero),
		"offsets": offsets,
	}
}

func rebuildGoldenStage7BpfMapCatalog(t *testing.T) any {
	t.Helper()

	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("loadBpf: %v", err)
	}
	names := make([]string, 0, len(spec.Maps))
	for name := range spec.Maps {
		names = append(names, name)
	}
	sort.Strings(names)
	maps := make([]map[string]any, 0, len(names))
	for _, name := range names {
		m := spec.Maps[name]
		maps = append(maps, map[string]any{
			"name":        name,
			"type":        fmt.Sprint(m.Type),
			"key_size":    m.KeySize,
			"value_size":  m.ValueSize,
			"max_entries": m.MaxEntries,
			"flags":       m.Flags,
			"pinning":     fmt.Sprint(m.Pinning),
		})
	}
	return map[string]any{
		"name": "stage7-bpf-map-catalog",
		"source": []string{
			"control/kern/tproxy.c",
			"control/bpf_bpfel.go",
		},
		"maps": maps,
		"pinned_reuse": []string{
			"cookie_pid_map",
			"routing_tuples_map",
			"tgid_pname_map",
		},
		"incompatible_pinned_map_policy": "delete pinned map by parsed map name and retry load once through the same fullLoadBpfObjects path",
	}
}

func rebuildGoldenStage7KernelFeatures() any {
	type feature struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Code    uint32 `json:"kernel_code"`
	}
	features := []feature{
		{"basic", consts.BasicFeatureVersion.String(), consts.BasicFeatureVersion.Kernel()},
		{"checksum", consts.ChecksumFeatureVersion.String(), consts.ChecksumFeatureVersion.Kernel()},
		{"sk_assign", consts.SkAssignFeatureVersion.String(), consts.SkAssignFeatureVersion.Kernel()},
		{"bpf_timer", consts.BpfTimerFeatureVersion.String(), consts.BpfTimerFeatureVersion.Kernel()},
		{"bpf_loop", consts.BpfLoopFeatureVersion.String(), consts.BpfLoopFeatureVersion.Kernel()},
	}
	return map[string]any{
		"name": "stage7-kernel-feature-gates",
		"source": []string{
			"control/control_plane.go",
			"common/consts/ebpf.go",
			"pkg/ebpf_internal/version.go",
		},
		"features": features,
		"scenarios": []map[string]any{
			kernelScenario("v5.1", internal.Version{5, 1, 0}, false, false),
			kernelScenario("v5.8", internal.Version{5, 8, 0}, false, false),
			kernelScenario("v5.10-lan", internal.Version{5, 10, 0}, true, false),
			kernelScenario("v5.15-wan", internal.Version{5, 15, 0}, false, true),
			kernelScenario("v5.17-full", internal.Version{5, 17, 0}, true, true),
		},
	}
}

func kernelScenario(name string, version internal.Version, lan, wan bool) map[string]any {
	var missing []string
	if version.Less(consts.BasicFeatureVersion) {
		missing = append(missing, "basic")
	}
	if version.Less(consts.ChecksumFeatureVersion) {
		missing = append(missing, "checksum")
	}
	if lan && version.Less(consts.SkAssignFeatureVersion) {
		missing = append(missing, "sk_assign_for_lan")
	}
	if wan && version.Less(consts.BpfTimerFeatureVersion) {
		missing = append(missing, "bpf_timer_for_wan")
	}
	if version.Less(consts.BpfLoopFeatureVersion) {
		missing = append(missing, "bpf_loop")
	}
	return map[string]any{
		"name":           name,
		"version":        version.String(),
		"lan_configured": lan,
		"wan_configured": wan,
		"missing":        missing,
		"allowed":        len(missing) == 0,
	}
}

func rebuildGoldenStage7DomainRoutingTracker(t *testing.T) any {
	t.Helper()

	tracker := newDomainRoutingTracker()
	ownerA := domainRoutingOwnerSnapshot{
		bitmap: domainBitmap(0x3),
		ips: map[[4]uint32]struct{}{
			domainIpKey("192.0.2.1"):   {},
			domainIpKey("2001:db8::1"): {},
		},
	}
	ownerB := domainRoutingOwnerSnapshot{
		bitmap: domainBitmap(0x4),
		ips: map[[4]uint32]struct{}{
			domainIpKey("192.0.2.1"):    {},
			domainIpKey("198.51.100.7"): {},
		},
	}
	ownerBReplace := domainRoutingOwnerSnapshot{
		bitmap: domainBitmap(0x10),
		ips: map[[4]uint32]struct{}{
			domainIpKey("198.51.100.7"): {},
			domainIpKey("2001:db8::2"):  {},
		},
	}

	steps := make([]map[string]any, 0, 4)
	if err := tracker.syncOwner(nil, "q=a.example|type=A|class=IN", ownerA); err != nil {
		t.Fatalf("sync owner A: %v", err)
	}
	steps = append(steps, domainTrackerView("after_owner_a", tracker))
	if err := tracker.syncOwner(nil, "q=b.example|type=A|class=IN", ownerB); err != nil {
		t.Fatalf("sync owner B: %v", err)
	}
	steps = append(steps, domainTrackerView("after_owner_b", tracker))
	if err := tracker.syncOwner(nil, "q=a.example|type=A|class=IN", domainRoutingOwnerSnapshot{}); err != nil {
		t.Fatalf("remove owner A: %v", err)
	}
	steps = append(steps, domainTrackerView("after_remove_owner_a", tracker))
	if err := tracker.syncOwner(nil, "q=b.example|type=A|class=IN", ownerBReplace); err != nil {
		t.Fatalf("replace owner B: %v", err)
	}
	steps = append(steps, domainTrackerView("after_replace_owner_b", tracker))

	return map[string]any{
		"name": "stage7-domain-routing-owner-tracker",
		"source": []string{
			"control/domain_routing_tracker.go",
			"control/domain_routing_tracker_test.go",
		},
		"owner_commit_rule": "kernel map update/delete succeeds before tracker memory state is applied",
		"steps":             steps,
	}
}

func domainBitmap(words ...uint32) bpfDomainRouting {
	var bitmap bpfDomainRouting
	copy(bitmap.Bitmap[:], words)
	return bitmap
}

func domainIpKey(s string) [4]uint32 {
	ip := netip.MustParseAddr(s).As16()
	return common.Ipv6ByteSliceToUint32Array(ip[:])
}

func domainKeyToIP(key [4]uint32) string {
	b := common.Ipv6Uint32ArrayToByteSlice(key)
	addr, ok := netip.AddrFromSlice(b)
	if !ok {
		return fmt.Sprintf("%08x:%08x:%08x:%08x", key[0], key[1], key[2], key[3])
	}
	return addr.Unmap().String()
}

func bitmapWords(bitmap bpfDomainRouting) []uint32 {
	last := len(bitmap.Bitmap)
	for last > 0 && bitmap.Bitmap[last-1] == 0 {
		last--
	}
	out := make([]uint32, last)
	copy(out, bitmap.Bitmap[:last])
	return out
}

func domainTrackerView(name string, tracker *domainRoutingTracker) map[string]any {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	ips := make([]string, 0, len(tracker.ips))
	for key := range tracker.ips {
		ips = append(ips, domainKeyToIP(key))
	}
	sort.Strings(ips)
	entries := make([]map[string]any, 0, len(ips))
	for _, ip := range ips {
		var selected [4]uint32
		for key := range tracker.ips {
			if domainKeyToIP(key) == ip {
				selected = key
				break
			}
		}
		state := tracker.ips[selected]
		owners := make([]string, 0, len(state.owners))
		for owner := range state.owners {
			owners = append(owners, owner)
		}
		sort.Strings(owners)
		entries = append(entries, map[string]any{
			"ip":      ip,
			"owners":  owners,
			"merged":  bitmapWords(state.merged),
			"present": true,
		})
	}
	ownerKeys := make([]string, 0, len(tracker.owners))
	for owner := range tracker.owners {
		ownerKeys = append(ownerKeys, owner)
	}
	sort.Strings(ownerKeys)
	return map[string]any{
		"step":   name,
		"owners": ownerKeys,
		"ips":    entries,
	}
}

func rebuildGoldenStage7ReloadBpfOwnership() any {
	savedFlip := coreFlip
	defer func() { coreFlip = savedFlip }()
	coreFlip = 0

	obj := &bpfObjects{}
	fresh := newControlPlaneCore(logrus.New(), obj, nil, &internal.Version{5, 17, 0}, nil, false)
	steps := []map[string]any{coreOwnershipView("fresh_init", fresh)}
	_ = fresh.EjectBpf()
	steps = append(steps, coreOwnershipView("after_eject", fresh))
	fresh.InjectBpf(obj)
	steps = append(steps, coreOwnershipView("after_inject", fresh))

	reload := newControlPlaneCore(logrus.New(), obj, nil, &internal.Version{5, 17, 0}, nil, true)
	steps = append(steps, coreOwnershipView("reload_init", reload))
	_ = reload.EjectBpf()
	steps = append(steps, coreOwnershipView("reload_after_eject", reload))

	return map[string]any{
		"name": "stage7-reload-bpf-ownership",
		"source": []string{
			"control/control_plane_core.go",
			"control/control_plane.go",
			"engine/runtime.go",
		},
		"steps": steps,
		"rule":  "fresh core owns bpf.Close until EjectBpf removes it; reload core starts without bpf.Close and toggles coreFlip",
	}
}

func rebuildGoldenStage14ActiveDatapathOptInContract() any {
	encodedMagicNetwork := common.MagicNetwork("tcp", 1234, true)
	return map[string]any{
		"name": "stage14-active-datapath-optin-contract",
		"source": []string{
			"control/rust_active_datapath_optin.go",
			"control/control_plane.go",
			"control/control_plane_core.go",
			"control/netns_utils.go",
			"control/kern/tproxy.c",
			"engine/runtime.go",
			"rust/crates/dae-cli/src/active_datapath_runner.rs",
			"DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage14",
		},
		"notes": "Stage 14 adds a Rust active-datapath opt-in preflight gate before Go control plane loads eBPF; default Go attach, tproxy and reload behavior stay unchanged unless DAE_RUST_ACTIVE_DATAPATH_OPTIN is explicitly enabled.",
		"opt_in": map[string]any{
			"enable_env":          rustActiveDatapathOptInEnv,
			"helper_env":          rustActiveDatapathHelperEnv,
			"helper_default":      rustActiveDatapathHelperDefault,
			"disabled_is_go_path": true,
			"helper_timeout":      rustActiveDatapathHelperTimeout.String(),
			"rollback":            "unset DAE_RUST_ACTIVE_DATAPATH_OPTIN before daemon start or reload",
		},
		"helper_commands": map[string]any{
			"preflight": []string{
				"dae-cli-optin", "active-datapath", "preflight",
				"--tproxy-port", "12345",
				"--so-mark", "1234",
				"--mptcp", "true",
				"--lan-count", "1",
				"--wan-count", "0",
			},
			"contract":   []string{"dae-cli-optin", "active-datapath", "contract"},
			"reload":     []string{"dae-cli-optin", "active-datapath", "reload-ownership"},
			"magic_dial": []string{"dae-cli-optin", "active-datapath", "magic-dial", "--network", "tcp", "--mark", "1234", "--mptcp", "true"},
		},
		"active_path_gate": map[string]any{
			"called_from":             "control.NewControlPlane",
			"called_before":           "rlimit.RemoveMemlock, netns setup, fullLoadBpfObjects, tc attach, tproxy listeners",
			"requires_explicit_env":   true,
			"default_go_attach_path":  true,
			"helper_failure_aborts":   true,
			"pre_side_effect_failure": true,
		},
		"required_environment": []map[string]any{
			{"name": "root", "required": true},
			{"name": "bpffs", "required": true},
			{"name": "netns_permission", "required": true},
			{"name": "memlock", "required": true},
			{"name": "kernel_feature_version", "required": true},
		},
		"ebpf_loader": map[string]any{
			"pin_root":                       consts.BpfPinRoot,
			"pinned_reuse_maps":              []string{"cookie_pid_map", "routing_tuples_map", "tgid_pname_map"},
			"incompatible_pinned_map_action": "delete pinned map and retry",
			"tproxy_port_big_endian":         common.Htons(12345),
			"listen_socket_map_keys":         []int{0, 1},
			"map_catalog_fixture":            "ebpf/maps/catalog.json",
		},
		"attach_order": []string{
			"kernel feature gate",
			"remove memlock",
			"netns setup",
			"load or reuse eBPF objects",
			"bind LAN tc filters",
			"bind WAN tc/cgroup filters",
			"bind dae0/dae0peer tc filters",
			"build routing kernspace/userspace",
			"create DNS controller",
			"ListenAndServe writes TCP/UDP sockets into listen_socket_map",
		},
		"reload": map[string]any{
			"fixture":                          "control/reload_bpf_ownership/eject_inject.json",
			"fresh_owns_bpf_close":             true,
			"eject_removes_bpf_close":          true,
			"reload_core_starts_without_close": true,
			"rollback_injects_old_bpf":         true,
			"dns_cache_snapshot_required":      true,
			"listener_reuse_required":          true,
		},
		"tcp_udp": map[string]any{
			"tcp_sniff_before_bpf_result":   true,
			"tcp_relay_uses_sniffer_reader": true,
			"tcp_route_dial_can_reroute":    true,
			"udp_53_dns_controller":         true,
			"udp_must_rules_bypass_dns":     true,
			"udp_quic_sniff_can_reroute":    true,
			"udp_quic_target_stays_ip":      true,
			"udp_endpoint_pool_fixture":     "datapath/udp_pools/basic.json",
			"packet_sniffer_pool_required":  true,
		},
		"magic_network": map[string]any{
			"network":        "tcp",
			"mark":           1234,
			"mptcp":          true,
			"encoded_b64":    base64.StdEncoding.EncodeToString([]byte(encodedMagicNetwork)),
			"is_plain":       encodedMagicNetwork == "tcp",
			"active_path":    true,
			"preserve_mark":  true,
			"preserve_mptcp": true,
		},
		"netns_same_interface_risk": map[string]any{
			"fixture_source":             "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:34",
			"lan_wan_same_physical_port": true,
			"tc_act_pipe_required":       true,
			"do_not_reorder_tc_filters":  true,
			"netkit_native_attach_defer": true,
		},
	}
}

func coreOwnershipView(step string, core *controlPlaneCore) map[string]any {
	return map[string]any{
		"step":             step,
		"is_reload":        core.isReload,
		"bpf_ejected":      core.bpfEjected,
		"defer_func_count": len(core.deferFuncs),
		"flip":             core.flip,
	}
}

func rebuildGoldenStage7OutboundConnectivity() any {
	type event struct {
		Name     string
		Outbound uint8
		Network  *dialer.NetworkType
		Alive    bool
		IsInit   bool
		Dryrun   bool
	}
	events := []event{
		{
			Name:     "dryrun_init_tcp4_alive",
			Outbound: 2,
			Network:  networkType(consts.L4ProtoStr_TCP, consts.IpVersionStr_4),
			Alive:    true,
			IsInit:   true,
			Dryrun:   true,
		},
		{
			Name:     "dryrun_runtime_tcp4_dead_skipped",
			Outbound: 2,
			Network:  networkType(consts.L4ProtoStr_TCP, consts.IpVersionStr_4),
			Alive:    false,
			IsInit:   false,
			Dryrun:   true,
		},
		{
			Name:     "ip_mode_runtime_udp6_dead_written",
			Outbound: 3,
			Network:  networkType(consts.L4ProtoStr_UDP, consts.IpVersionStr_6),
			Alive:    false,
			IsInit:   false,
			Dryrun:   false,
		},
	}
	records := make([]map[string]any, 0, len(events))
	state := map[string]uint32{}
	for _, e := range events {
		written := e.IsInit || !e.Dryrun
		key := connectivityKeyString(e.Outbound, e.Network)
		if written {
			if e.Alive {
				state[key] = 1
			} else {
				state[key] = 0
			}
		}
		records = append(records, map[string]any{
			"name":      e.Name,
			"written":   written,
			"key":       connectivityKey(e.Outbound, e.Network),
			"value":     state[key],
			"state_len": len(state),
		})
	}
	return map[string]any{
		"name": "stage7-outbound-connectivity-dryrun",
		"source": []string{
			"control/connectivity.go",
			"common/consts/dialer.go",
		},
		"events": records,
		"rule":   "dryrun updates write only during init; ip dial mode updates every runtime alive change",
	}
}

func networkType(l4 consts.L4ProtoStr, ip consts.IpVersionStr) *dialer.NetworkType {
	return &dialer.NetworkType{
		L4Proto:   l4,
		IpVersion: ip,
		IsDns:     false,
	}
}

func connectivityKey(outbound uint8, networkType *dialer.NetworkType) map[string]any {
	return map[string]any{
		"outbound":  outbound,
		"l4proto":   networkType.L4Proto.ToL4Proto(),
		"ipversion": networkType.IpVersion.ToIpVersion(),
		"label":     networkType.StringWithoutDns(),
	}
}

func connectivityKeyString(outbound uint8, networkType *dialer.NetworkType) string {
	return fmt.Sprintf("%d/%d/%d", outbound, networkType.L4Proto.ToL4Proto(), networkType.IpVersion.ToIpVersion())
}

func rebuildGoldenStage7UdpPools() any {
	return map[string]any{
		"name": "stage7-udp-and-sniffer-pools",
		"source": []string{
			"control/udp.go",
			"control/udp_endpoint_pool.go",
			"control/udp_task_pool.go",
			"control/packet_sniffer_pool.go",
		},
		"udp_endpoint_pool": map[string]any{
			"default_max_entries": defaultUdpEndpointPoolMaxEntries,
			"normalize": []map[string]any{
				{"input": -1, "output": normalizeUdpEndpointPoolMaxEntries(-1)},
				{"input": 0, "output": normalizeUdpEndpointPoolMaxEntries(0)},
				{"input": 8, "output": normalizeUdpEndpointPoolMaxEntries(8)},
			},
			"trim_target": []map[string]any{
				{"max_entries": 1, "target": udpEndpointPoolTrimTarget(1)},
				{"max_entries": 20, "target": udpEndpointPoolTrimTarget(20)},
				{"max_entries": 4096, "target": udpEndpointPoolTrimTarget(4096)},
			},
			"default_nat_timeout_ms": int64(DefaultNatTimeout / 1_000_000),
			"dns_nat_timeout_ms":     int64(DnsNatTimeout / 1_000_000),
			"anyfrom_timeout_ms":     int64(AnyfromTimeout / 1_000_000),
			"max_retry":              MaxRetry,
		},
		"udp_task_pool": map[string]any{
			"queue_length":  UdpTaskQueueLength,
			"max_queues":    udpTaskPoolMaxQueues,
			"drop_rule":     "EmitTask returns false and increments droppedTasks when the per-key queue is full or no idle queue can be evicted",
			"ordering_rule": "accepted tasks for the same key execute through one convoy queue and keep FIFO order",
		},
		"packet_sniffer_pool": map[string]any{
			"ttl_ms":      int64(PacketSnifferTtl / 1_000_000),
			"max_entries": packetSnifferPoolMaxEntries,
			"evict_rule":  "GetOrCreate evicts expired first, otherwise the oldest lastActive sniffer",
		},
	}
}

func rebuildGoldenStage7RouteLoop() any {
	return map[string]any{
		"name": "stage7-route-loop-model",
		"source": []string{
			"control/kern/tproxy.c",
			"control/routing_matcher_builder.go",
			"common/consts/ebpf.go",
		},
		"cases": []map[string]any{
			{
				"name": "fallback_only",
				"rules": []map[string]any{
					{"index": 0, "type": "Fallback", "outbound": uint8(consts.OutboundDirect), "mark": uint32(0), "must": false, "matched": true},
				},
				"expected": map[string]any{"outbound": uint8(consts.OutboundDirect), "mark": uint32(0), "must": false, "fallback": true},
			},
			{
				"name": "must_rule_preserves_must",
				"rules": []map[string]any{
					{"index": 0, "type": "DomainSet", "outbound": uint8(consts.OutboundMustRules), "mark": uint32(0), "must": true, "matched": true},
					{"index": 1, "type": "Fallback", "outbound": uint8(consts.OutboundDirect), "mark": uint32(0), "must": false, "matched": true},
				},
				"expected": map[string]any{"outbound": uint8(consts.OutboundMustRules), "mark": uint32(0), "must": true, "fallback": false},
			},
			{
				"name": "first_matching_user_rule_wins",
				"rules": []map[string]any{
					{"index": 0, "type": "IpSet", "outbound": uint8(7), "mark": uint32(0x1234), "must": false, "matched": false},
					{"index": 1, "type": "Port", "outbound": uint8(8), "mark": uint32(consts.TproxyMark), "must": false, "matched": true},
					{"index": 2, "type": "Fallback", "outbound": uint8(consts.OutboundBlock), "mark": uint32(0), "must": false, "matched": true},
				},
				"expected": map[string]any{"outbound": uint8(8), "mark": uint32(consts.TproxyMark), "must": false, "fallback": false},
			},
		},
	}
}

func rebuildGoldenStage7MagicNetwork() any {
	cases := []map[string]any{}
	for _, tc := range []struct {
		name    string
		network string
		mark    uint32
		mptcp   bool
	}{
		{"plain_tcp", "tcp", 0, false},
		{"tcp_mark", "tcp", consts.TproxyMark, false},
		{"tcp_mptcp", "tcp", 0, true},
		{"udp_mark_mptcp", "udp", 0x123456, true},
	} {
		encoded := common.MagicNetwork(tc.network, tc.mark, tc.mptcp)
		cases = append(cases, map[string]any{
			"name":        tc.name,
			"network":     tc.network,
			"mark":        tc.mark,
			"mptcp":       tc.mptcp,
			"encoded_b64": base64.StdEncoding.EncodeToString([]byte(encoded)),
			"is_plain":    encoded == tc.network,
			"length":      len([]byte(encoded)),
		})
	}
	return map[string]any{
		"name": "stage7-active-dial-magic-network",
		"source": []string{
			"common/utils.go",
			"control/tcp.go",
			"control/udp.go",
		},
		"cases": cases,
		"rule":  "active TCP/UDP dial must pass common.MagicNetwork(network, mark, mptcp), not the plain network string when mark or mptcp is set",
	}
}

func BenchmarkRebuildStage7DomainRoutingOwnerMerge(b *testing.B) {
	ownerA := domainRoutingOwnerSnapshot{
		bitmap: domainBitmap(0x3, 0x8),
		ips: map[[4]uint32]struct{}{
			domainIpKey("192.0.2.1"):   {},
			domainIpKey("2001:db8::1"): {},
		},
	}
	ownerB := domainRoutingOwnerSnapshot{
		bitmap: domainBitmap(0x4),
		ips: map[[4]uint32]struct{}{
			domainIpKey("192.0.2.1"):    {},
			domainIpKey("198.51.100.7"): {},
		},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tracker := newDomainRoutingTracker()
		if err := tracker.syncOwner(nil, "a", ownerA); err != nil {
			b.Fatal(err)
		}
		if err := tracker.syncOwner(nil, "b", ownerB); err != nil {
			b.Fatal(err)
		}
		if err := tracker.syncOwner(nil, "a", domainRoutingOwnerSnapshot{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRebuildStage7MagicNetworkMarkMptcp(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = common.MagicNetwork("tcp", consts.TproxyMark, true)
	}
}

func BenchmarkRebuildStage7UdpEndpointTrimTarget(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = udpEndpointPoolTrimTarget(4096)
	}
}
