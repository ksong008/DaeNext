//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package main_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/component/routing/domain_matcher"
	"github.com/daeuniverse/dae/component/sniffing"
	daeconfig "github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/geodata"
	"github.com/daeuniverse/dae/pkg/trie"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

const rebuildGoldenUpdateEnv = "DAE_UPDATE_REBUILD_GOLDEN"

func TestWriteRebuildGoldenFixtures(t *testing.T) {
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/abi/consts/reserved_indices.json", rebuildGoldenReservedIndices())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/abi/consts/dial_mode_policy.json", rebuildGoldenDialModePolicy())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/abi/magic_network/mark_mptcp.json", rebuildGoldenMagicNetwork(t))
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/config/fuzzy/basic.json", rebuildGoldenFuzzyDecode())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/config/parse/basic.json", rebuildGoldenConfigParse())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/config/parser/ast_basic.json", rebuildGoldenConfigParserAst(t))
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/config/schema/default_patch.json", rebuildGoldenConfigSchemaDefaultPatch(t))
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/config/include/merger.json", rebuildGoldenConfigIncludeMerger(t))
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/config/marshal/example_roundtrip.json", rebuildGoldenConfigMarshalRoundtrip(t))
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/config/outline/export_outline.json", rebuildGoldenConfigOutline(t))
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/config/utils/basic.json", rebuildGoldenConfigUtils(t))
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/config/utils/common.json", rebuildGoldenCommonUtils())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/routing/prefix/bare_ip_to_host_prefix.json", rebuildGoldenRoutingPrefix(t))
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/routing/trie/reversed_domain_prefix.json", rebuildGoldenRoutingTrie(t))
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/routing/domain_matcher/basic_bitmap.json", rebuildGoldenRoutingDomainMatcher(t))
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/routing/userspace/basic_matcher.json", rebuildGoldenRoutingUserspace(t))
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/geodata/streaming/basic.json", rebuildGoldenGeodataStreaming(t))
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/sniffing/basic.json", rebuildGoldenSniffingBasic(t))
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/dns/cache_key/basic.json", rebuildGoldenDnsCacheKey())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/dns/cache/ttl_eviction_stats.json", rebuildGoldenDnsCacheTtlEvictionStats())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/dns/packed_response/basic.json", rebuildGoldenDnsPackedResponse(t))
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/dns/validation/question_and_id.json", rebuildGoldenDnsValidation())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/dns/doh/get_post_validation.json", rebuildGoldenDnsDoh())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/dns/netutils/basic.json", rebuildGoldenDnsNetutils())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/dns/upstream/resolver_refresh.json", rebuildGoldenDnsUpstreamResolver())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/dns/resolve_ip46/asis_original_target_guard.json", rebuildGoldenDnsResolveIp46Guard())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/outbound/group/fixed.json", rebuildGoldenOutboundGroupFixed())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/outbound/group/min_last_latency.json", rebuildGoldenOutboundGroupMinLastLatency())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/outbound/group/min_avg10.json", rebuildGoldenOutboundGroupMinAvg10())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/outbound/group/min_moving_avg.json", rebuildGoldenOutboundGroupMinMovingAvg())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/outbound/group/random_alive.json", rebuildGoldenOutboundGroupRandomAlive())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/outbound/group/ipversion_fallback_no_mutation.json", rebuildGoldenOutboundGroupIpVersionFallback())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/outbound/filter/name_and_subscription_tag.json", rebuildGoldenOutboundFilterNameSubtag())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/outbound/filter/bad_regex.json", rebuildGoldenOutboundFilterBadRegex())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/outbound/dialer/lazy_state.json", rebuildGoldenOutboundDialerLazyState())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/outbound/alive_set/random_skips_latency_state.json", rebuildGoldenOutboundAliveRandomSkipsLatency())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/outbound/alive_set/latency_offset_sparse.json", rebuildGoldenOutboundAliveLatencyOffsetSparse())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/outbound/direct/injected_resolver.json", rebuildGoldenOutboundDirectInjectedResolver())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/outbound/protocol/ss2022_no_global_direct_dependency.json", rebuildGoldenOutboundProtocolSS2022())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/outbound/group_override/clone_profile_key.json", rebuildGoldenOutboundGroupOverrideCloneProfile())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/outbound/connectivity/map_dimensions.json", rebuildGoldenOutboundConnectivityMapDimensions())
	writeOrCheckRebuildGolden(t, "testdata/rebuild-golden/outbound/link_parser/compatibility_matrix.json", rebuildGoldenOutboundLinkParserCompatibility())
}

func writeOrCheckRebuildGolden(t *testing.T, path string, value any) {
	t.Helper()

	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	data = append(data, '\n')

	if os.Getenv(rebuildGoldenUpdateEnv) == "1" {
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
	if !jsonEqual(want, data) {
		t.Fatalf("%s does not match generated golden; run %s=1 go test . -run TestWriteRebuildGoldenFixtures", path, rebuildGoldenUpdateEnv)
	}
}

func jsonEqual(a, b []byte) bool {
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

func rebuildGoldenReservedIndices() any {
	return map[string]any{
		"name": "reserved-indices",
		"source": []string{
			"common/consts/ebpf.go",
			"common/consts/dns.go",
			"common/consts/reload.go",
		},
		"notes": "Rust core types must keep these values byte-for-byte compatible with Go daex.",
		"outbound": map[string]any{
			"direct": map[string]any{
				"value":    uint8(consts.OutboundDirect),
				"string":   consts.OutboundDirect.String(),
				"reserved": consts.OutboundDirect.IsReserved(),
			},
			"block": map[string]any{
				"value":    uint8(consts.OutboundBlock),
				"string":   consts.OutboundBlock.String(),
				"reserved": consts.OutboundBlock.IsReserved(),
			},
			"user_defined_min": uint8(consts.OutboundUserDefinedMin),
			"user_defined_max": uint8(consts.OutboundUserDefinedMax),
			"must_rules": map[string]any{
				"value":    uint8(consts.OutboundMustRules),
				"hex":      "0xfc",
				"string":   consts.OutboundMustRules.String(),
				"reserved": consts.OutboundMustRules.IsReserved(),
			},
			"control_plane_routing": map[string]any{
				"value":    uint8(consts.OutboundControlPlaneRouting),
				"hex":      "0xfd",
				"string":   consts.OutboundControlPlaneRouting.String(),
				"reserved": consts.OutboundControlPlaneRouting.IsReserved(),
			},
			"logical_or": map[string]any{
				"value":    uint8(consts.OutboundLogicalOr),
				"hex":      "0xfe",
				"string":   consts.OutboundLogicalOr.String(),
				"reserved": consts.OutboundLogicalOr.IsReserved(),
			},
			"logical_and": map[string]any{
				"value":    uint8(consts.OutboundLogicalAnd),
				"hex":      "0xff",
				"string":   consts.OutboundLogicalAnd.String(),
				"reserved": consts.OutboundLogicalAnd.IsReserved(),
			},
			"logical_mask": map[string]any{
				"value": uint8(consts.OutboundLogicalMask),
				"hex":   "0xfe",
			},
			"example_user_defined": map[string]any{
				"value":    2,
				"string":   consts.OutboundIndex(2).String(),
				"reserved": consts.OutboundIndex(2).IsReserved(),
			},
		},
		"dns_request": map[string]any{
			"reject": map[string]any{
				"value":  int16(consts.DnsRequestOutboundIndex_Reject),
				"hex":    "0xfc",
				"string": consts.DnsRequestOutboundIndex_Reject.String(),
			},
			"asis": map[string]any{
				"value":  int16(consts.DnsRequestOutboundIndex_AsIs),
				"hex":    "0xfd",
				"string": consts.DnsRequestOutboundIndex_AsIs.String(),
			},
			"logical_or": map[string]any{
				"value":  int16(consts.DnsRequestOutboundIndex_LogicalOr),
				"hex":    "0xfe",
				"string": consts.DnsRequestOutboundIndex_LogicalOr.String(),
			},
			"logical_and": map[string]any{
				"value":  int16(consts.DnsRequestOutboundIndex_LogicalAnd),
				"hex":    "0xff",
				"string": consts.DnsRequestOutboundIndex_LogicalAnd.String(),
			},
			"logical_mask": map[string]any{
				"value": int16(consts.DnsRequestOutboundIndex_LogicalMask),
				"hex":   "0xfe",
			},
			"user_defined_max": int16(consts.DnsRequestOutboundIndex_UserDefinedMax),
			"example_user_defined": map[string]any{
				"value":  2,
				"string": consts.DnsRequestOutboundIndex(2).String(),
			},
		},
		"dns_response": map[string]any{
			"accept": map[string]any{
				"value":    uint8(consts.DnsResponseOutboundIndex_Accept),
				"hex":      "0xfc",
				"string":   consts.DnsResponseOutboundIndex_Accept.String(),
				"reserved": consts.DnsResponseOutboundIndex_Accept.IsReserved(),
			},
			"reject": map[string]any{
				"value":    uint8(consts.DnsResponseOutboundIndex_Reject),
				"hex":      "0xfd",
				"string":   consts.DnsResponseOutboundIndex_Reject.String(),
				"reserved": consts.DnsResponseOutboundIndex_Reject.IsReserved(),
			},
			"logical_or": map[string]any{
				"value":    uint8(consts.DnsResponseOutboundIndex_LogicalOr),
				"hex":      "0xfe",
				"string":   consts.DnsResponseOutboundIndex_LogicalOr.String(),
				"reserved": consts.DnsResponseOutboundIndex_LogicalOr.IsReserved(),
			},
			"logical_and": map[string]any{
				"value":    uint8(consts.DnsResponseOutboundIndex_LogicalAnd),
				"hex":      "0xff",
				"string":   consts.DnsResponseOutboundIndex_LogicalAnd.String(),
				"reserved": consts.DnsResponseOutboundIndex_LogicalAnd.IsReserved(),
			},
			"logical_mask": map[string]any{
				"value": uint8(consts.DnsResponseOutboundIndex_LogicalMask),
				"hex":   "0xfe",
			},
			"user_defined_max": uint8(consts.DnsResponseOutboundIndex_UserDefinedMax),
			"example_user_defined": map[string]any{
				"value":    2,
				"string":   consts.DnsResponseOutboundIndex(2).String(),
				"reserved": consts.DnsResponseOutboundIndex(2).IsReserved(),
			},
		},
		"reload": map[string]any{
			"send":       reloadStateFixture(consts.ReloadSend),
			"processing": reloadStateFixture(consts.ReloadProcessing),
			"done":       reloadStateFixture(consts.ReloadDone),
			"error":      reloadStateFixture(consts.ReloadError),
		},
		"tproxy": map[string]any{
			"mark":             consts.TproxyMark,
			"mark_hex":         consts.TproxyMarkString,
			"recognize":        consts.Recognize,
			"recognize_hex":    "0x2017",
			"loopback_ifindex": consts.LoopbackIfIndex,
			"task_comm_len":    consts.TaskCommLen,
			"bpf_pin_root":     consts.BpfPinRoot,
		},
	}
}

func reloadStateFixture(code byte) map[string]any {
	return map[string]any{
		"byte": int(code),
		"char": string([]byte{code}),
	}
}

func rebuildGoldenDialModePolicy() any {
	return map[string]any{
		"name": "dial-mode-policy",
		"source": []string{
			"common/consts/app.go",
			"common/consts/control.go",
			"common/consts/dialer.go",
		},
		"notes":    "These string values are user-visible config/API compatibility values.",
		"app_name": consts.AppName,
		"dial_modes": map[string]any{
			"accepted": []string{
				string(consts.DialMode_Ip),
				string(consts.DialMode_Domain),
				string(consts.DialMode_DomainPlus),
				string(consts.DialMode_DomainCao),
			},
			"rejected_examples": []string{"", "auto", "DOMAIN", "domain_plus"},
			"error_format":      "unsupported dial mode: <mode>",
		},
		"dialer_selection_policies": []string{
			string(consts.DialerSelectionPolicy_Random),
			string(consts.DialerSelectionPolicy_Fixed),
			string(consts.DialerSelectionPolicy_MinAverage10Latencies),
			string(consts.DialerSelectionPolicy_MinMovingAverageLatencies),
			string(consts.DialerSelectionPolicy_MinLastLatency),
		},
		"network_dimensions": map[string]any{
			"l4_proto": map[string]any{
				"tcp": string(consts.L4ProtoStr_TCP),
				"udp": string(consts.L4ProtoStr_UDP),
			},
			"ip_version": map[string]any{
				"ipv4": string(consts.IpVersionStr_4),
				"ipv6": string(consts.IpVersionStr_6),
			},
		},
		"defaults": map[string]any{
			"udp_check_lookup_host": consts.UdpCheckLookupHost,
			"default_dial_timeout":  consts.DefaultDialTimeout.String(),
		},
	}
}

func rebuildGoldenMagicNetwork(t *testing.T) any {
	t.Helper()

	cases := []map[string]any{
		magicNetworkCase(t, "plain-tcp", "tcp", 0, false, true),
		magicNetworkCase(t, "tcp-mark-only", "tcp", 1280, false, false),
		magicNetworkCase(t, "udp-mptcp-only", "udp", 0, true, false),
		magicNetworkCase(t, "tcp-mark-and-mptcp", "tcp", consts.TproxyMark, true, false),
	}
	return map[string]any{
		"name": "magic-network-mark-mptcp",
		"source": []string{
			"common/utils.go:MagicNetwork",
			"github.com/daeuniverse/outbound/netproxy.MagicNetwork",
		},
		"notes": "MagicNetwork is the ABI that carries SO_MARK and MPTCP through outbound/netproxy DialContext network strings.",
		"cases": cases,
	}
}

func magicNetworkCase(t *testing.T, name string, network string, mark uint32, mptcp bool, printable bool) map[string]any {
	t.Helper()

	encoded := common.MagicNetwork(network, mark, mptcp)
	parsed, err := netproxy.ParseMagicNetwork(encoded)
	if err != nil {
		t.Fatalf("parse magic network %s: %v", name, err)
	}
	want := map[string]any{
		"encoded_hex": hex.EncodeToString([]byte(encoded)),
		"parsed": map[string]any{
			"network": parsed.Network,
			"mark":    parsed.Mark,
			"mptcp":   parsed.Mptcp,
		},
	}
	if printable {
		want["encoded_printable"] = encoded
	}
	return map[string]any{
		"name": name,
		"input": map[string]any{
			"network": network,
			"mark":    mark,
			"mptcp":   mptcp,
		},
		"want": want,
	}
}

func rebuildGoldenFuzzyDecode() any {
	return map[string]any{
		"name":   "fuzzy-decode-basic",
		"source": "common/utils.go:FuzzyDecode",
		"notes":  "Rust config utilities must keep Go FuzzyDecode compatibility for defaults, overlays, and config parsing.",
		"cases": []any{
			map[string]any{
				"name":   "bool-true-aliases",
				"target": "bool",
				"inputs": []string{"true", "t", "1", "y", "yes", "on", "TRUE", "On"},
				"want":   true,
			},
			map[string]any{
				"name":   "bool-false-aliases",
				"target": "bool",
				"inputs": []string{"false", "f", "0", "n", "no", "off", "FALSE", "Off"},
				"want":   false,
			},
			map[string]any{
				"name":    "bool-invalid",
				"target":  "bool",
				"inputs":  []string{"", "maybe", "enabled"},
				"want_ok": false,
			},
			map[string]any{
				"name":   "int-base-zero",
				"target": "int",
				"inputs": []any{
					map[string]any{"value": "16", "want": fuzzyInt("16")},
					map[string]any{"value": "0x10", "want": fuzzyInt("0x10")},
					map[string]any{"value": "010", "want": fuzzyInt("010")},
				},
				"want_ok": true,
			},
			map[string]any{
				"name":   "uint16-limit",
				"target": "uint16",
				"inputs": []any{
					map[string]any{"value": "65535", "want": fuzzyUint16("65535"), "ok": true},
					map[string]any{"value": "65536", "ok": fuzzyUint16OK("65536")},
				},
			},
			map[string]any{
				"name":   "duration",
				"target": "time.Duration",
				"inputs": []any{
					map[string]any{"value": "30s", "want": fuzzyDuration("30s"), "ok": true},
					map[string]any{"value": "1m30s", "want": fuzzyDuration("1m30s"), "ok": true},
					map[string]any{"value": "-1.5s", "want": fuzzyDuration("-1.5s"), "ok": true},
					map[string]any{"value": "1.5h", "want": fuzzyDuration("1.5h"), "ok": true},
					map[string]any{"value": "1500ms", "want": fuzzyDuration("1500ms"), "ok": true},
					map[string]any{"value": "500us", "want": fuzzyDuration("500us"), "ok": true},
					map[string]any{"value": "30", "ok": fuzzyDurationOK("30")},
				},
			},
			map[string]any{
				"name":   "string",
				"target": "string",
				"inputs": []any{
					map[string]any{"value": "unchanged", "want": fuzzyString("unchanged")},
					map[string]any{"value": "", "want": fuzzyString("")},
				},
				"want_ok": true,
			},
			map[string]any{
				"name":   "url-or-empty",
				"target": "common.UrlOrEmpty",
				"inputs": []any{
					map[string]any{"value": "", "want": fuzzyURLOrEmpty(""), "ok": true},
					map[string]any{"value": "https://example.com/path", "want": fuzzyURLOrEmpty("https://example.com/path"), "ok": true},
					map[string]any{"value": "/relative/path", "want": fuzzyURLOrEmpty("/relative/path"), "ok": true},
					map[string]any{"value": "example.com/path", "want": fuzzyURLOrEmpty("example.com/path"), "ok": true},
					map[string]any{"value": "%zz", "ok": fuzzyURLOrEmptyOK("%zz")},
				},
			},
			map[string]any{
				"name":   "string-slice",
				"target": "[]string",
				"inputs": []any{
					map[string]any{"value": "a,b,c", "want": fuzzyStringSlice("a,b,c"), "ok": true},
					map[string]any{"value": "", "want": fuzzyStringSlice(""), "ok": true},
				},
			},
			map[string]any{
				"name":   "duration-slice-single",
				"target": "[]time.Duration",
				"inputs": []any{
					map[string]any{"value": "5s", "want": fuzzyDurationSlice("5s"), "ok": true},
					map[string]any{"value": "1.5s", "want": fuzzyDurationSlice("1.5s"), "ok": true},
					map[string]any{"value": "5s,10s", "ok": fuzzyDurationSliceOK("5s,10s")},
				},
			},
		},
	}
}

func fuzzyInt(input string) int {
	var out int
	_ = common.FuzzyDecode(&out, input)
	return out
}

func fuzzyUint16(input string) uint16 {
	var out uint16
	_ = common.FuzzyDecode(&out, input)
	return out
}

func fuzzyUint16OK(input string) bool {
	var out uint16
	return common.FuzzyDecode(&out, input)
}

func fuzzyDuration(input string) string {
	var out time.Duration
	_ = common.FuzzyDecode(&out, input)
	return out.String()
}

func fuzzyDurationOK(input string) bool {
	var out time.Duration
	return common.FuzzyDecode(&out, input)
}

func fuzzyString(input string) string {
	var out string
	_ = common.FuzzyDecode(&out, input)
	return out
}

func fuzzyURLOrEmpty(input string) map[string]any {
	var out common.UrlOrEmpty
	_ = common.FuzzyDecode(&out, input)
	var urlValue any
	if out.Url != nil {
		urlValue = out.Url.String()
	}
	return map[string]any{
		"empty": out.Empty,
		"url":   urlValue,
	}
}

func fuzzyURLOrEmptyOK(input string) bool {
	var out common.UrlOrEmpty
	return common.FuzzyDecode(&out, input)
}

func fuzzyStringSlice(input string) []string {
	var out []string
	_ = common.FuzzyDecode(&out, input)
	return out
}

func fuzzyDurationSlice(input string) []string {
	var out []time.Duration
	_ = common.FuzzyDecode(&out, input)
	values := make([]string, 0, len(out))
	for _, v := range out {
		values = append(values, v.String())
	}
	return values
}

func fuzzyDurationSliceOK(input string) bool {
	var out []time.Duration
	return common.FuzzyDecode(&out, input)
}

func rebuildGoldenConfigParse() any {
	return map[string]any{
		"name":   "config-parse-basic",
		"source": "common/utils.go:ParseMac,ParsePortRange",
		"notes":  "Rust config utilities must keep Go ParseMac and ParsePortRange compatibility for config/routing parsing.",
		"port_ranges": []any{
			portRangeCase("single", "80"),
			portRangeCase("range", "100-200"),
			portRangeCase("empty", ""),
			portRangeCase("empty-start", "-1"),
			portRangeCase("empty-end", "1-"),
			portRangeCase("too-large", "65536"),
			portRangeCase("invalid-decimal", "abc"),
		},
		"macs": []any{
			macCase("valid", "00:11:22:aa:BB:cc"),
			macCase("too-few-fields", "00:11:22:aa:bb"),
			macCase("one-digit-field", "0:11:22:aa:bb:cc"),
		},
	}
}

func portRangeCase(name string, input string) map[string]any {
	got, err := common.ParsePortRange(input)
	out := map[string]any{
		"name":  name,
		"input": input,
		"ok":    err == nil,
	}
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	out["want"] = []uint16{got[0], got[1]}
	return out
}

func macCase(name string, input string) map[string]any {
	got, err := common.ParseMac(input)
	out := map[string]any{
		"name":  name,
		"input": input,
		"ok":    err == nil,
	}
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	out["want_hex"] = hex.EncodeToString(got[:])
	return out
}

func rebuildGoldenConfigParserAst(t *testing.T) any {
	t.Helper()

	return map[string]any{
		"name": "config-parser-ast-basic",
		"source": []string{
			"pkg/config_parser/config_parser.go",
			"pkg/config_parser/walker.go",
			"pkg/config_parser/section.go",
			"pkg/config_parser/error.go",
		},
		"notes": "Deterministic projection of Go config_parser AST. item_type records Item.Type.String(); value_kind records the actual Value type.",
		"cases": []any{
			configParserAstCase(t, "mixed-sections-params-functions-routing", `
include {
    child.dae
}

global {
    tcp_check_url: 'https://connectivity.example/generate_204',1.1.1.1
    dial_mode: domain
}

node {
    my_node: 'socks5://127.0.0.1:1080'
    'https://example.com/no_tag'
}

group {
    test_group {
        filter: !name(keyword:'hk', regex:'^HK') && subtag(my_sub) [add_latency: -500ms]
        policy: fixed(0)
    }
}

routing {
    domain(geosite:cn) -> direct
    domain(suffix:example.com) -> proxy(mark: 1)
    fallback: test_group
}
`),
			configParserAstCase(t, "empty-function-parameter-list-error", `
group {
    test_group {
        filter: name()
    }
}
`),
			configParserAstCase(t, "first-syntax-error", `
global {
    tproxy_port:
}
`),
		},
	}
}

func configParserAstCase(t *testing.T, name string, input string) map[string]any {
	t.Helper()

	sections, err := config_parser.Parse(input)
	out := map[string]any{
		"name":  name,
		"input": input,
		"ok":    err == nil,
	}
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	out["sections"] = projectConfigParserSections(sections)
	return out
}

type rebuildGoldenParserSection struct {
	Name  string                    `json:"name"`
	Items []rebuildGoldenParserItem `json:"items"`
}

type rebuildGoldenParserItem struct {
	ItemType    string                          `json:"item_type"`
	ValueKind   string                          `json:"value_kind"`
	Param       *rebuildGoldenParserParam       `json:"param,omitempty"`
	Section     *rebuildGoldenParserSection     `json:"section,omitempty"`
	RoutingRule *rebuildGoldenParserRoutingRule `json:"routing_rule,omitempty"`
}

type rebuildGoldenParserParam struct {
	Key          string                        `json:"key"`
	Val          string                        `json:"val"`
	AndFunctions []rebuildGoldenParserFunction `json:"and_functions,omitempty"`
	Annotation   []rebuildGoldenParserParam    `json:"annotation,omitempty"`
}

type rebuildGoldenParserFunction struct {
	Name   string                     `json:"name"`
	Not    bool                       `json:"not"`
	Params []rebuildGoldenParserParam `json:"params"`
}

type rebuildGoldenParserRoutingRule struct {
	AndFunctions []rebuildGoldenParserFunction `json:"and_functions"`
	Outbound     rebuildGoldenParserFunction   `json:"outbound"`
}

func projectConfigParserSections(sections []*config_parser.Section) []rebuildGoldenParserSection {
	out := make([]rebuildGoldenParserSection, 0, len(sections))
	for _, section := range sections {
		out = append(out, projectConfigParserSection(section))
	}
	return out
}

func projectConfigParserSection(section *config_parser.Section) rebuildGoldenParserSection {
	out := rebuildGoldenParserSection{
		Name:  section.Name,
		Items: make([]rebuildGoldenParserItem, 0, len(section.Items)),
	}
	for _, item := range section.Items {
		out.Items = append(out.Items, projectConfigParserItem(item))
	}
	return out
}

func projectConfigParserItem(item *config_parser.Item) rebuildGoldenParserItem {
	out := rebuildGoldenParserItem{
		ItemType:  item.Type.String(),
		ValueKind: configParserValueKind(item.Value),
	}
	switch value := item.Value.(type) {
	case *config_parser.Param:
		param := projectConfigParserParam(value)
		out.Param = &param
	case *config_parser.Section:
		section := projectConfigParserSection(value)
		out.Section = &section
	case *config_parser.RoutingRule:
		rule := projectConfigParserRoutingRule(value)
		out.RoutingRule = &rule
	}
	return out
}

func configParserValueKind(value any) string {
	switch value.(type) {
	case *config_parser.Param:
		return "Param"
	case *config_parser.Section:
		return "Section"
	case *config_parser.RoutingRule:
		return "RoutingRule"
	default:
		if value == nil {
			return "<nil>"
		}
		return reflect.TypeOf(value).String()
	}
}

func projectConfigParserParam(param *config_parser.Param) rebuildGoldenParserParam {
	out := rebuildGoldenParserParam{
		Key: param.Key,
		Val: param.Val,
	}
	if param.AndFunctions != nil {
		out.AndFunctions = projectConfigParserFunctions(param.AndFunctions)
	}
	if param.Annotation != nil {
		out.Annotation = make([]rebuildGoldenParserParam, 0, len(param.Annotation))
		for _, annotation := range param.Annotation {
			out.Annotation = append(out.Annotation, projectConfigParserParam(annotation))
		}
	}
	return out
}

func projectConfigParserFunctions(functions []*config_parser.Function) []rebuildGoldenParserFunction {
	out := make([]rebuildGoldenParserFunction, 0, len(functions))
	for _, function := range functions {
		out = append(out, projectConfigParserFunction(function))
	}
	return out
}

func projectConfigParserFunction(function *config_parser.Function) rebuildGoldenParserFunction {
	return rebuildGoldenParserFunction{
		Name:   function.Name,
		Not:    function.Not,
		Params: projectConfigParserParams(function.Params),
	}
}

func projectConfigParserParams(params []*config_parser.Param) []rebuildGoldenParserParam {
	out := make([]rebuildGoldenParserParam, 0, len(params))
	for _, param := range params {
		out = append(out, projectConfigParserParam(param))
	}
	return out
}

func projectConfigParserRoutingRule(rule *config_parser.RoutingRule) rebuildGoldenParserRoutingRule {
	return rebuildGoldenParserRoutingRule{
		AndFunctions: projectConfigParserFunctions(rule.AndFunctions),
		Outbound:     projectConfigParserFunction(&rule.Outbound),
	}
}

func rebuildGoldenConfigSchemaDefaultPatch(t *testing.T) any {
	t.Helper()

	return map[string]any{
		"name": "config-schema-default-patch",
		"source": []string{
			"config/config.go",
			"config/parser.go",
			"config/patch.go",
			"pkg/config_parser/config_parser.go",
		},
		"notes": "Deterministic projection of typed config.New output after defaults, required checks, and patches.",
		"cases": []any{
			configSchemaCase(t, "minimal-defaults", `
global {}
routing {}
`),
			configSchemaCase(t, "include-section-is-ignored", `
include {
    child.dae
}
global {}
routing {}
`),
			configSchemaCase(t, "slice-override-append-invalid-method-and-must-outbound", `
global {
    tcp_check_url: 'https://one.example/check,1.1.1.1'
    tcp_check_url: 'https://two.example/check'
    udp_check_dns: 'dns.one:53'
    lan_interface: eth0,eth1
    wan_interface: auto
    fallback_resolver: '[2001:4860:4860::8888]:53'
    tcp_check_http_method: BREW
}

routing {
    domain(geosite:cn) -> must_direct
    domain(geosite:ads) -> must_rules
    fallback: must_direct
}
`),
			configSchemaCase(t, "repeatable-group-filter-annotation", `
global {}
group {
    proxy {
        filter: name(HK)
        filter: name(US) [add_latency: -500ms]
        policy: min_avg10
    }
}
routing {}
`),
			configSchemaCase(t, "explicit-dns-routing", `
global {}
dns {
    upstream {
        alidns: 'udp://dns.alidns.com:53'
        googledns: 'tcp+udp://dns.google:53'
    }
    routing {
        request {
            qname(geosite:cn) -> alidns
            fallback: googledns
        }
        response {
            upstream(googledns) -> accept
            fallback: reject
        }
    }
}
routing {}
`),
			configSchemaCase(t, "missing-global-section", `
routing {}
`),
			configSchemaCase(t, "missing-routing-section", `
global {}
`),
			configSchemaCase(t, "unknown-top-level-section", `
global {}
routing {}
unknown {}
`),
			configSchemaCase(t, "missing-group-policy", `
global {}
group {
    proxy {
        filter: name(HK)
    }
}
routing {}
`),
			configSchemaCase(t, "unknown-global-key", `
global {
    no_such_key: 1
}
routing {}
`),
			configSchemaCase(t, "invalid-fallback-resolver", `
global {
    fallback_resolver: bad-resolver
}
routing {}
`),
			configSchemaCase(t, "invalid-routing-fallback-function-list", `
global {}
routing {
    fallback: fixed(0) && fixed(1)
}
`),
		},
	}
}

func configSchemaCase(t *testing.T, name string, input string) map[string]any {
	t.Helper()

	out := map[string]any{
		"name":  name,
		"input": input,
	}
	sections, err := config_parser.Parse(input)
	if err != nil {
		out["ok"] = false
		out["phase"] = "parse"
		out["error"] = err.Error()
		return out
	}
	conf, err := daeconfig.New(sections)
	if err != nil {
		out["ok"] = false
		out["phase"] = "build"
		out["error"] = err.Error()
		return out
	}
	out["ok"] = true
	out["config"] = projectConfigSchema(conf)
	return out
}

type rebuildGoldenConfigSchema struct {
	Global       rebuildGoldenGlobalSchema  `json:"global"`
	Subscription []string                   `json:"subscription"`
	Node         []string                   `json:"node"`
	Group        []rebuildGoldenGroupSchema `json:"group"`
	Routing      rebuildGoldenRoutingSchema `json:"routing"`
	DNS          rebuildGoldenDNSSchema     `json:"dns"`
}

type rebuildGoldenGlobalSchema struct {
	TproxyPort                 uint16   `json:"tproxy_port"`
	TproxyPortProtect          bool     `json:"tproxy_port_protect"`
	SoMarkFromDae              uint32   `json:"so_mark_from_dae"`
	LogLevel                   string   `json:"log_level"`
	TcpCheckUrl                []string `json:"tcp_check_url"`
	TcpCheckHttpMethod         string   `json:"tcp_check_http_method"`
	UdpCheckDns                []string `json:"udp_check_dns"`
	CheckInterval              string   `json:"check_interval"`
	CheckTolerance             string   `json:"check_tolerance"`
	UdpEndpointPoolSize        int      `json:"udp_endpoint_pool_size"`
	LanInterface               []string `json:"lan_interface"`
	WanInterface               []string `json:"wan_interface"`
	AllowInsecure              bool     `json:"allow_insecure"`
	DialMode                   string   `json:"dial_mode"`
	DisableWaitingNetwork      bool     `json:"disable_waiting_network"`
	EnableLocalTcpFastRedirect bool     `json:"enable_local_tcp_fast_redirect"`
	AutoConfigKernelParameter  bool     `json:"auto_config_kernel_parameter"`
	AutoConfigFirewallRule     bool     `json:"auto_config_firewall_rule"`
	SniffingTimeout            string   `json:"sniffing_timeout"`
	TlsImplementation          string   `json:"tls_implementation"`
	UtlsImitate                string   `json:"utls_imitate"`
	TlsFragment                bool     `json:"tls_fragment"`
	TlsFragmentLength          string   `json:"tls_fragment_length"`
	TlsFragmentInterval        string   `json:"tls_fragment_interval"`
	PprofPort                  uint16   `json:"pprof_port"`
	Mptcp                      bool     `json:"mptcp"`
	FallbackResolver           string   `json:"fallback_resolver"`
	BandwidthMaxTx             string   `json:"bandwidth_max_tx"`
	BandwidthMaxRx             string   `json:"bandwidth_max_rx"`
	UDPHopInterval             string   `json:"udphop_interval"`
}

type rebuildGoldenGroupSchema struct {
	Name               string                            `json:"name"`
	Filter             [][]rebuildGoldenParserFunction   `json:"filter"`
	FilterAnnotation   [][]rebuildGoldenParserParam      `json:"filter_annotation"`
	Policy             rebuildGoldenDynamicFunctionValue `json:"policy"`
	TcpCheckUrl        []string                          `json:"tcp_check_url"`
	TcpCheckHttpMethod string                            `json:"tcp_check_http_method"`
	UdpCheckDns        []string                          `json:"udp_check_dns"`
	CheckInterval      string                            `json:"check_interval"`
	CheckTolerance     string                            `json:"check_tolerance"`
}

type rebuildGoldenRoutingSchema struct {
	Rules    []rebuildGoldenParserRoutingRule  `json:"rules"`
	Fallback rebuildGoldenDynamicFunctionValue `json:"fallback"`
}

type rebuildGoldenDNSSchema struct {
	IpVersionPrefer int                     `json:"ipversion_prefer"`
	FixedDomainTtl  []string                `json:"fixed_domain_ttl"`
	Upstream        []string                `json:"upstream"`
	Routing         rebuildGoldenDNSRouting `json:"routing"`
	Bind            string                  `json:"bind"`
}

type rebuildGoldenDNSRouting struct {
	Request  rebuildGoldenDNSRuleSet `json:"request"`
	Response rebuildGoldenDNSRuleSet `json:"response"`
}

type rebuildGoldenDNSRuleSet struct {
	Rules    []rebuildGoldenParserRoutingRule  `json:"rules"`
	Fallback rebuildGoldenDynamicFunctionValue `json:"fallback"`
}

type rebuildGoldenDynamicFunctionValue struct {
	Kind      string                        `json:"kind"`
	String    string                        `json:"string,omitempty"`
	Function  *rebuildGoldenParserFunction  `json:"function,omitempty"`
	Functions []rebuildGoldenParserFunction `json:"functions,omitempty"`
}

func projectConfigSchema(conf *daeconfig.Config) rebuildGoldenConfigSchema {
	groups := make([]rebuildGoldenGroupSchema, 0, len(conf.Group))
	for _, group := range conf.Group {
		groups = append(groups, projectConfigGroupSchema(group))
	}
	return rebuildGoldenConfigSchema{
		Global:       projectConfigGlobalSchema(conf.Global),
		Subscription: projectKeyableStrings(conf.Subscription),
		Node:         projectKeyableStrings(conf.Node),
		Group:        groups,
		Routing: rebuildGoldenRoutingSchema{
			Rules:    projectConfigParserRoutingRules(conf.Routing.Rules),
			Fallback: projectDynamicFunctionValue(conf.Routing.Fallback),
		},
		DNS: projectConfigDNSSchema(conf.Dns),
	}
}

func projectConfigGlobalSchema(global daeconfig.Global) rebuildGoldenGlobalSchema {
	return rebuildGoldenGlobalSchema{
		TproxyPort:                 global.TproxyPort,
		TproxyPortProtect:          global.TproxyPortProtect,
		SoMarkFromDae:              global.SoMarkFromDae,
		LogLevel:                   global.LogLevel,
		TcpCheckUrl:                global.TcpCheckUrl,
		TcpCheckHttpMethod:         global.TcpCheckHttpMethod,
		UdpCheckDns:                global.UdpCheckDns,
		CheckInterval:              global.CheckInterval.String(),
		CheckTolerance:             global.CheckTolerance.String(),
		UdpEndpointPoolSize:        global.UdpEndpointPoolSize,
		LanInterface:               global.LanInterface,
		WanInterface:               global.WanInterface,
		AllowInsecure:              global.AllowInsecure,
		DialMode:                   global.DialMode,
		DisableWaitingNetwork:      global.DisableWaitingNetwork,
		EnableLocalTcpFastRedirect: global.EnableLocalTcpFastRedirect,
		AutoConfigKernelParameter:  global.AutoConfigKernelParameter,
		AutoConfigFirewallRule:     global.AutoConfigFirewallRule,
		SniffingTimeout:            global.SniffingTimeout.String(),
		TlsImplementation:          global.TlsImplementation,
		UtlsImitate:                global.UtlsImitate,
		TlsFragment:                global.TlsFragment,
		TlsFragmentLength:          global.TlsFragmentLength,
		TlsFragmentInterval:        global.TlsFragmentInterval,
		PprofPort:                  global.PprofPort,
		Mptcp:                      global.Mptcp,
		FallbackResolver:           global.FallbackResolver,
		BandwidthMaxTx:             global.BandwidthMaxTx,
		BandwidthMaxRx:             global.BandwidthMaxRx,
		UDPHopInterval:             global.UDPHopInterval.String(),
	}
}

func projectConfigGroupSchema(group daeconfig.Group) rebuildGoldenGroupSchema {
	return rebuildGoldenGroupSchema{
		Name:               group.Name,
		Filter:             projectConfigParserFunctionMatrix(group.Filter),
		FilterAnnotation:   projectConfigParserParamMatrix(group.FilterAnnotation),
		Policy:             projectDynamicFunctionValue(group.Policy),
		TcpCheckUrl:        group.TcpCheckUrl,
		TcpCheckHttpMethod: group.TcpCheckHttpMethod,
		UdpCheckDns:        group.UdpCheckDns,
		CheckInterval:      group.CheckInterval.String(),
		CheckTolerance:     group.CheckTolerance.String(),
	}
}

func projectConfigDNSSchema(dns daeconfig.Dns) rebuildGoldenDNSSchema {
	return rebuildGoldenDNSSchema{
		IpVersionPrefer: dns.IpVersionPrefer,
		FixedDomainTtl:  projectKeyableStrings(dns.FixedDomainTtl),
		Upstream:        projectKeyableStrings(dns.Upstream),
		Routing: rebuildGoldenDNSRouting{
			Request: rebuildGoldenDNSRuleSet{
				Rules:    projectConfigParserRoutingRules(dns.Routing.Request.Rules),
				Fallback: projectDynamicFunctionValue(dns.Routing.Request.Fallback),
			},
			Response: rebuildGoldenDNSRuleSet{
				Rules:    projectConfigParserRoutingRules(dns.Routing.Response.Rules),
				Fallback: projectDynamicFunctionValue(dns.Routing.Response.Fallback),
			},
		},
		Bind: dns.Bind,
	}
}

func projectKeyableStrings(values []daeconfig.KeyableString) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}

func projectDynamicFunctionValue(value any) rebuildGoldenDynamicFunctionValue {
	switch value := value.(type) {
	case nil:
		return rebuildGoldenDynamicFunctionValue{Kind: "nil"}
	case string:
		return rebuildGoldenDynamicFunctionValue{Kind: "string", String: value}
	case *config_parser.Function:
		function := projectConfigParserFunction(value)
		return rebuildGoldenDynamicFunctionValue{Kind: "function", Function: &function}
	case []*config_parser.Function:
		return rebuildGoldenDynamicFunctionValue{Kind: "function_list", Functions: projectConfigParserFunctions(value)}
	default:
		return rebuildGoldenDynamicFunctionValue{Kind: reflect.TypeOf(value).String()}
	}
}

func projectConfigParserRoutingRules(rules []*config_parser.RoutingRule) []rebuildGoldenParserRoutingRule {
	out := make([]rebuildGoldenParserRoutingRule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, projectConfigParserRoutingRule(rule))
	}
	return out
}

func projectConfigParserFunctionMatrix(matrix [][]*config_parser.Function) [][]rebuildGoldenParserFunction {
	out := make([][]rebuildGoldenParserFunction, len(matrix))
	for i, functions := range matrix {
		if functions == nil {
			continue
		}
		out[i] = projectConfigParserFunctions(functions)
	}
	return out
}

func projectConfigParserParamMatrix(matrix [][]*config_parser.Param) [][]rebuildGoldenParserParam {
	out := make([][]rebuildGoldenParserParam, len(matrix))
	for i, params := range matrix {
		if params == nil {
			continue
		}
		out[i] = projectConfigParserParams(params)
	}
	return out
}

func rebuildGoldenConfigIncludeMerger(t *testing.T) any {
	t.Helper()

	return map[string]any{
		"name": "config-include-merger",
		"source": []string{
			"config/config_merger.go",
			"common/utils.go:EnsureFileInSubDir",
			"config/config.go",
		},
		"notes": "Config include merger golden uses real temp files and normalizes temp paths to $ROOT in error text.",
		"cases": []any{
			includeMergerSuccessCase(t),
			includeMergerDuplicateCase(t),
			includeMergerPathEscapeCase(t),
			includeMergerTooOpenCase(t),
			includeMergerBadEntrySuffixCase(t),
			includeMergerUnsupportedGrammarCase(t),
		},
	}
}

func includeMergerSuccessCase(t *testing.T) map[string]any {
	t.Helper()

	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "config.d"))
	mustMkdirAll(t, filepath.Join(root, "config.d", "dir.dae"))
	mustWriteFileMode(t, filepath.Join(root, "entry.dae"), []byte(`
include {
    config.d/*
    missing/*.dae
}
global {
    log_level: info
}
routing {
    fallback: parent
}
`), 0640)
	mustWriteFileMode(t, filepath.Join(root, "config.d", "child.dae"), []byte(`
include {
    nested.dae
}
global {
    log_level: debug
}
routing {
    domain(child.example) -> child
}
`), 0640)
	mustWriteFileMode(t, filepath.Join(root, "nested.dae"), []byte(`
global {
    tcp_check_http_method: POST
}
node {
    nested: 'socks5://nested'
}
routing {
    domain(nested.example) -> nested
    fallback: nested
}
`), 0640)
	mustWriteFileMode(t, filepath.Join(root, "config.d", "ignored.txt"), []byte(`global {}`), 0640)

	out := runIncludeMergerCase(t, "success-relative-top-entry-dir-glob-filter-child-append", root, filepath.Join(root, "entry.dae"))
	out["expect"] = []string{
		"config.d/* keeps config.d/child.dae and filters ignored.txt plus dir.dae directory",
		"missing glob returns nil without error",
		"nested.dae from child include is resolved against top entry dir",
		"child/nested section items are appended after parent items",
	}
	return out
}

func includeMergerDuplicateCase(t *testing.T) map[string]any {
	t.Helper()

	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "config.d"))
	mustWriteFileMode(t, filepath.Join(root, "entry.dae"), []byte(`
include {
    config.d/child.dae
    config.d/child.dae
}
global {}
routing {}
`), 0640)
	mustWriteFileMode(t, filepath.Join(root, "config.d", "child.dae"), []byte(`
global {}
routing {}
`), 0640)
	return runIncludeMergerCase(t, "duplicate-include-reuses-circular-error", root, filepath.Join(root, "entry.dae"))
}

func includeMergerPathEscapeCase(t *testing.T) map[string]any {
	t.Helper()

	base := t.TempDir()
	root := filepath.Join(base, "root")
	mustMkdirAll(t, root)
	mustWriteFileMode(t, filepath.Join(root, "entry.dae"), []byte(`
include {
    ../outside.dae
}
global {}
routing {}
`), 0640)
	mustWriteFileMode(t, filepath.Join(base, "outside.dae"), []byte(`
global {}
routing {}
`), 0640)
	return runIncludeMergerCase(t, "path-escape-rejected", base, filepath.Join(root, "entry.dae"))
}

func includeMergerTooOpenCase(t *testing.T) map[string]any {
	t.Helper()

	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "config.d"))
	mustWriteFileMode(t, filepath.Join(root, "entry.dae"), []byte(`
include {
    config.d/open.dae
}
global {}
routing {}
`), 0640)
	mustWriteFileMode(t, filepath.Join(root, "config.d", "open.dae"), []byte(`
global {}
routing {}
`), 0644)
	return runIncludeMergerCase(t, "too-open-permission-rejected", root, filepath.Join(root, "entry.dae"))
}

func includeMergerBadEntrySuffixCase(t *testing.T) map[string]any {
	t.Helper()

	root := t.TempDir()
	mustWriteFileMode(t, filepath.Join(root, "entry.conf"), []byte(`
global {}
routing {}
`), 0640)
	return runIncludeMergerCase(t, "bad-entry-suffix-rejected", root, filepath.Join(root, "entry.conf"))
}

func includeMergerUnsupportedGrammarCase(t *testing.T) map[string]any {
	t.Helper()

	root := t.TempDir()
	mustWriteFileMode(t, filepath.Join(root, "entry.dae"), []byte(`
include {
    child {
    }
}
global {}
routing {}
`), 0640)
	return runIncludeMergerCase(t, "unsupported-include-grammar", root, filepath.Join(root, "entry.dae"))
}

func runIncludeMergerCase(t *testing.T, name string, root string, entry string) map[string]any {
	t.Helper()

	sections, entries, err := daeconfig.NewMerger(entry).Merge()
	out := map[string]any{
		"name":  name,
		"entry": normalizeRootPath(entry, root),
		"ok":    err == nil,
	}
	if err != nil {
		out["error"] = normalizeRootPath(err.Error(), root)
		return out
	}

	out["entries"] = projectMergerEntries(t, root, entries)
	out["sections"] = projectConfigParserSectionsSorted(sections)
	conf, err := daeconfig.New(sections)
	if err != nil {
		out["config_ok"] = false
		out["config_error"] = normalizeRootPath(err.Error(), root)
		return out
	}
	out["config_ok"] = true
	out["config"] = projectConfigSchema(conf)
	return out
}

func projectMergerEntries(t *testing.T, root string, entries []string) []string {
	t.Helper()

	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		rel, err := filepath.Rel(root, entry)
		if err != nil || strings.HasPrefix(rel, "..") {
			out = append(out, normalizeRootPath(entry, root))
			continue
		}
		out = append(out, filepath.ToSlash(rel))
	}
	sort.Strings(out)
	return out
}

func projectConfigParserSectionsSorted(sections []*config_parser.Section) []rebuildGoldenParserSection {
	out := projectConfigParserSections(sections)
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func normalizeRootPath(value string, root string) string {
	cleanRoot := filepath.Clean(root)
	return strings.ReplaceAll(value, cleanRoot, "$ROOT")
}

func rebuildGoldenConfigMarshalRoundtrip(t *testing.T) any {
	t.Helper()

	example, err := os.ReadFile("example.dae")
	if err != nil {
		t.Fatalf("read example.dae: %v", err)
	}

	root := t.TempDir()
	entry := filepath.Join(root, "example.dae")
	mustWriteFileMode(t, entry, example, 0640)

	sections, entries, err := daeconfig.NewMerger(entry).Merge()
	if err != nil {
		t.Fatalf("merge example.dae: %v", err)
	}
	conf1, err := daeconfig.New(sections)
	if err != nil {
		t.Fatalf("build example.dae config: %v", err)
	}
	marshaled, err := conf1.Marshal(2)
	if err != nil {
		t.Fatalf("marshal example.dae config: %v", err)
	}

	roundtripEntry := filepath.Join(root, "roundtrip.dae")
	mustWriteFileMode(t, roundtripEntry, marshaled, 0640)
	roundtripSections, _, err := daeconfig.NewMerger(roundtripEntry).Merge()
	if err != nil {
		t.Fatalf("merge roundtrip.dae: %v", err)
	}
	conf2, err := daeconfig.New(roundtripSections)
	if err != nil {
		t.Fatalf("build roundtrip.dae config: %v", err)
	}

	normalized1 := normalizeConfigForRebuildGolden(conf1)
	normalized2 := normalizeConfigForRebuildGolden(conf2)
	sum := sha256.Sum256(marshaled)
	return map[string]any{
		"name": "config-marshal-example-roundtrip",
		"source": []string{
			"example.dae",
			"config/marshal.go",
			"config/marshal_test.go",
		},
		"notes":   "Roundtrip equality follows config/marshal_test.go and clears Group.FilterAnnotation before compare because annotations are parse metadata not marshaled output.",
		"input":   "example.dae",
		"entries": projectMergerEntries(t, root, entries),
		"marshal": map[string]any{
			"indent": 2,
			"len":    len(marshaled),
			"sha256": hex.EncodeToString(sum[:]),
			"text":   string(marshaled),
		},
		"roundtrip": map[string]any{
			"equal_after_filter_annotation_clear": reflect.DeepEqual(normalized1, normalized2),
		},
		"normalized_config": projectConfigSchema(normalized1),
	}
}

func normalizeConfigForRebuildGolden(conf *daeconfig.Config) *daeconfig.Config {
	if conf == nil {
		return nil
	}
	normalized := *conf
	if conf.Group != nil {
		normalized.Group = make([]daeconfig.Group, len(conf.Group))
		copy(normalized.Group, conf.Group)
		for i := range normalized.Group {
			normalized.Group[i].FilterAnnotation = nil
		}
	}
	return &normalized
}

func rebuildGoldenConfigOutline(t *testing.T) any {
	t.Helper()

	var outline any
	if err := json.Unmarshal([]byte(daeconfig.ExportOutlineJson("test")), &outline); err != nil {
		t.Fatalf("unmarshal outline json: %v", err)
	}
	return map[string]any{
		"name": "config-outline-export-outline",
		"source": []string{
			"config/outline.go",
			"config/desc.go",
			"config/config.go",
		},
		"notes":   "Stable projection of config.ExportOutlineJson(\"test\") for Rust outline/FlatDesc parity.",
		"outline": outline,
	}
}

func rebuildGoldenRoutingPrefix(t *testing.T) any {
	t.Helper()

	inputs := []string{"192.0.2.1", "2001:db8::1", "2001:db8::/48"}
	var got []string
	parser := routing.IpParserFactory(func(_ *config_parser.Function, cidrs []netip.Prefix, _ *routing.Outbound) error {
		for _, cidr := range cidrs {
			got = append(got, cidr.String())
		}
		return nil
	})
	function := &config_parser.Function{Name: "ip"}
	if err := parser(logrus.New(), function, "", inputs, &routing.Outbound{Name: "direct"}); err != nil {
		t.Fatalf("parse prefixes: %v", err)
	}

	return map[string]any{
		"name": "routing-prefix-bare-ip-to-host-prefix",
		"source": []string{
			"component/routing/function_parser.go",
		},
		"notes": "Bare IP values must be converted to host prefixes before routing matcher/trie build.",
		"cases": []any{
			map[string]any{
				"inputs": inputs,
				"want":   got,
			},
		},
	}
}

func rebuildGoldenRoutingTrie(t *testing.T) any {
	t.Helper()

	keys := []string{
		"moc.cbatnetnoc.",
		"moc.cbatnetnoc^",
		"nc.",
		"nc.ude.ctsu.srorrim.pct_.sptth_",
	}
	tr, err := trie.NewTrie(keys, trie.NewValidChars([]byte("0123456789abcdefghijklmnopqrstuvwxyz-.^_")))
	if err != nil {
		t.Fatalf("build trie: %v", err)
	}
	queries := []string{
		"nc.tset^",
		"nc^",
		"nc.",
		"nc.^",
		"nc._",
		"n",
		"n^",
		"moc.cbatnetnoc^",
		"nc.ude.ctsu.srorrim.pct_.sptth_^",
	}
	cases := make([]any, 0, len(queries))
	for _, query := range queries {
		cases = append(cases, map[string]any{
			"query": query,
			"hit":   tr.HasPrefix(query),
		})
	}
	return map[string]any{
		"name": "routing-trie-reversed-domain-prefix",
		"source": []string{
			"pkg/trie/trie.go",
			"pkg/trie/trie_test.go",
		},
		"notes":   "Domain suffix/full matcher uses reversed strings and HasPrefix semantics.",
		"keys":    keys,
		"queries": cases,
	}
}

func rebuildGoldenRoutingDomainMatcher(t *testing.T) any {
	t.Helper()

	const bitLength = 96
	matcher := domain_matcher.NewAhocorasickSlimtrie(logrus.New(), bitLength)
	sets := []map[string]any{
		{"bit": 0, "key": string(consts.RoutingDomainKey_Suffix), "patterns": []string{"example.com"}},
		{"bit": 1, "key": string(consts.RoutingDomainKey_Suffix), "patterns": []string{".child.example.com"}},
		{"bit": 31, "key": string(consts.RoutingDomainKey_Keyword), "patterns": []string{"cdn"}},
		{"bit": 32, "key": string(consts.RoutingDomainKey_Full), "patterns": []string{"exact.example.org"}},
		{"bit": 63, "key": string(consts.RoutingDomainKey_Regex), "patterns": []string{`^api[0-9]+\.example\.net$`}},
	}
	for _, set := range sets {
		patterns := set["patterns"].([]string)
		matcher.AddSet(set["bit"].(int), patterns, consts.RoutingDomainKey(set["key"].(string)))
	}
	if err := matcher.Build(); err != nil {
		t.Fatalf("build domain matcher: %v", err)
	}
	queries := []string{
		"example.com",
		"www.example.com",
		"child.example.com",
		"a.child.example.com",
		"static.cdn.invalid",
		"exact.example.org.",
		"api12.example.net",
		"API12.EXAMPLE.NET",
		"invalid.test",
	}
	cases := make([]any, 0, len(queries))
	reuse := []uint32{0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc}
	for _, query := range queries {
		allocated := matcher.MatchDomainBitmap(query)
		reused := matcher.MatchDomainBitmapInto(query, reuse)
		cases = append(cases, map[string]any{
			"domain":          query,
			"bitmap":          allocated,
			"bitmap_reused":   reused,
			"reuse_same_bits": reflect.DeepEqual(allocated, reused),
		})
	}
	return map[string]any{
		"name": "routing-domain-matcher-basic-bitmap",
		"source": []string{
			"component/routing/domain_matcher.go",
			"component/routing/domain_matcher/ahocorasick_slimtrie.go",
			"component/routing/domain_matcher/bruteforce.go",
		},
		"notes":      "Bitmap words are the parity surface; bit index equals routing match-set index.",
		"bit_length": bitLength,
		"sets":       sets,
		"queries":    cases,
	}
}

func rebuildGoldenRoutingUserspace(t *testing.T) any {
	t.Helper()

	return map[string]any{
		"name": "routing-userspace-basic-matcher",
		"source": []string{
			"control/routing_matcher_userspace.go",
			"control/routing_matcher_userspace_test.go",
			"common/consts/ebpf.go",
		},
		"notes": "Projection of userspace matcher fallback/domain/ip+port cases from Go targeted tests.",
		"constants": map[string]any{
			"match_type": map[string]any{
				"domain_set": int(consts.MatchType_DomainSet),
				"ip_set":     int(consts.MatchType_IpSet),
				"port":       int(consts.MatchType_Port),
				"fallback":   int(consts.MatchType_Fallback),
			},
			"outbound": map[string]any{
				"direct":      int(consts.OutboundDirect),
				"block":       int(consts.OutboundBlock),
				"logical_or":  int(consts.OutboundLogicalOr),
				"logical_and": int(consts.OutboundLogicalAnd),
			},
		},
		"cases": []any{
			map[string]any{
				"name": "fallback-direct",
				"matcher": map[string]any{
					"matches": []any{
						map[string]any{"type": "fallback", "outbound": "direct"},
					},
				},
				"queries": []any{
					map[string]any{"dest": "203.0.113.42", "dest_port": 443, "domain": "", "want": "direct"},
				},
			},
			map[string]any{
				"name": "domain-suffix-direct-else-block",
				"matcher": map[string]any{
					"domain_sets": []any{
						map[string]any{"bit": 0, "key": "suffix", "patterns": []string{"example.com"}},
					},
					"matches": []any{
						map[string]any{"type": "domain_set", "outbound": "direct"},
						map[string]any{"type": "fallback", "outbound": "block"},
					},
				},
				"queries": []any{
					map[string]any{"dest": "203.0.113.42", "dest_port": 443, "domain": "www.example.com", "want": "direct"},
					map[string]any{"dest": "203.0.113.42", "dest_port": 443, "domain": "www.invalid.test", "want": "block"},
				},
			},
			map[string]any{
				"name": "ip-and-port-or-direct-else-block",
				"matcher": map[string]any{
					"lpm_sets": []any{
						map[string]any{"index": 0, "prefixes": []string{"203.0.113.0/24"}},
					},
					"matches": []any{
						map[string]any{"type": "ip_set", "lpm_index": 0, "outbound": "logical_or"},
						map[string]any{"type": "port", "port_start": 443, "port_end": 443, "outbound": "direct"},
						map[string]any{"type": "fallback", "outbound": "block"},
					},
				},
				"queries": []any{
					map[string]any{"dest": "203.0.113.42", "dest_port": 443, "domain": "", "want": "direct"},
					map[string]any{"dest": "198.51.100.42", "dest_port": 8443, "domain": "", "want": "block"},
				},
			},
		},
	}
}

func rebuildGoldenGeodataStreaming(t *testing.T) any {
	t.Helper()

	geoipBytes := mustMarshalProto(t, &geodata.GeoIPList{Entry: []*geodata.GeoIP{
		{
			CountryCode: "CN",
			Cidr: []*geodata.CIDR{
				{Ip: []byte{203, 0, 113, 0}, Prefix: 24},
				{Ip: netip.MustParseAddr("2001:db8::").AsSlice(), Prefix: 32},
			},
		},
		{
			CountryCode: "US",
			Cidr: []*geodata.CIDR{
				{Ip: []byte{198, 51, 100, 0}, Prefix: 24},
			},
		},
	}})
	geositeBytes := mustMarshalProto(t, &geodata.GeoSiteList{Entry: []*geodata.GeoSite{
		{
			CountryCode: "CN",
			Domain: []*geodata.Domain{
				{Type: geodata.Domain_Full, Value: "full.example.cn"},
				{Type: geodata.Domain_RootDomain, Value: "suffix.example.cn"},
				{Type: geodata.Domain_Plain, Value: "keyword-cn"},
				{Type: geodata.Domain_Regex, Value: `^api[0-9]+\.example\.cn$`},
			},
		},
		{
			CountryCode: "US",
			Domain: []*geodata.Domain{
				{Type: geodata.Domain_RootDomain, Value: "example.us"},
			},
		},
	}})
	corruptWithUnknownPrefix := append([]byte{0x10, 0x01}, geoipBytes...)

	root := t.TempDir()
	geoipPath := filepath.Join(root, "geoip.dat")
	geositePath := filepath.Join(root, "geosite.dat")
	corruptPath := filepath.Join(root, "geoip-corrupt-prefix.dat")
	mustWriteFileMode(t, geoipPath, geoipBytes, 0640)
	mustWriteFileMode(t, geositePath, geositeBytes, 0640)
	mustWriteFileMode(t, corruptPath, corruptWithUnknownPrefix, 0640)

	log := logrus.New()
	return map[string]any{
		"name": "geodata-streaming-basic",
		"source": []string{
			"pkg/geodata/decode.go",
			"pkg/geodata/geodata.go",
			"pkg/geodata/common.pb.go",
		},
		"notes":                    "Small protobuf dat files for streaming hit/miss and corrupt-prefix fallback parity.",
		"geoip_hex":                hex.EncodeToString(geoipBytes),
		"geosite_hex":              hex.EncodeToString(geositeBytes),
		"corrupt_geoip_prefix_hex": hex.EncodeToString(corruptWithUnknownPrefix),
		"cases": []any{
			geodataGeoIPCase(t, log, "geoip-hit-equalfold-cn", geoipPath, "cn"),
			geodataGeoIPCase(t, log, "geoip-hit-us", geoipPath, "US"),
			geodataGeoIPCase(t, log, "geoip-miss-zz", geoipPath, "ZZ"),
			geodataGeoSiteCase(t, log, "geosite-hit-equalfold-cn", geositePath, "cn"),
			geodataGeoSiteCase(t, log, "geosite-miss-zz", geositePath, "ZZ"),
			geodataGeoIPCase(t, log, "geoip-corrupt-prefix-fallback-cn", corruptPath, "CN"),
		},
	}
}

func geodataGeoIPCase(t *testing.T, log *logrus.Logger, name string, path string, code string) map[string]any {
	t.Helper()

	_, decodeErr := geodata.Decode(path, code)
	geoip, err := geodata.UnmarshalGeoIp(log, path, code)
	out := map[string]any{
		"name":        name,
		"kind":        "geoip",
		"code":        code,
		"decode_ok":   decodeErr == nil,
		"fallback_ok": decodeErr != nil && err == nil,
		"ok":          err == nil,
	}
	if decodeErr != nil {
		out["decode_error"] = decodeErr.Error()
	}
	if err != nil {
		out["error"] = stableGeodataError(err, path)
		return out
	}
	out["country_code"] = geoip.GetCountryCode()
	var cidrs []string
	for _, cidr := range geoip.GetCidr() {
		addr, ok := netip.AddrFromSlice(cidr.GetIp())
		if !ok {
			t.Fatalf("%s invalid cidr ip: %x", name, cidr.GetIp())
		}
		cidrs = append(cidrs, netip.PrefixFrom(addr, int(cidr.GetPrefix())).String())
	}
	out["cidrs"] = cidrs
	return out
}

func geodataGeoSiteCase(t *testing.T, log *logrus.Logger, name string, path string, code string) map[string]any {
	t.Helper()

	_, decodeErr := geodata.Decode(path, code)
	geosite, err := geodata.UnmarshalGeoSite(log, path, code)
	out := map[string]any{
		"name":        name,
		"kind":        "geosite",
		"code":        code,
		"decode_ok":   decodeErr == nil,
		"fallback_ok": decodeErr != nil && err == nil,
		"ok":          err == nil,
	}
	if decodeErr != nil {
		out["decode_error"] = decodeErr.Error()
	}
	if err != nil {
		out["error"] = stableGeodataError(err, path)
		return out
	}
	out["country_code"] = geosite.GetCountryCode()
	domains := make([]map[string]string, 0, len(geosite.GetDomain()))
	for _, domain := range geosite.GetDomain() {
		domains = append(domains, map[string]string{
			"type":  domain.GetType().String(),
			"value": domain.GetValue(),
		})
	}
	out["domains"] = domains
	return out
}

func mustMarshalProto(t testing.TB, message proto.Message) []byte {
	t.Helper()

	data, err := proto.Marshal(message)
	if err != nil {
		t.Fatalf("marshal proto: %v", err)
	}
	return data
}

func stableGeodataError(err error, path string) string {
	return strings.ReplaceAll(err.Error(), path, "<geodata-file>")
}

func rebuildGoldenSniffingBasic(t *testing.T) any {
	t.Helper()

	httpRequest := []byte("GET /path HTTP/1.1\r\nHost: Example.COM:443\r\nUser-Agent: dae\r\n\r\n")
	tlsGoogleHex := "1603010200010001fc0303d90fdf25b0c7a11c3eb968604a065157a149407c139c22ed32f5c6f486ed2c04206c51c32da7f83c3c19766be60d45d264e898c77504e34915c44caa69513c2221003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff0100017500000013001100000e7777772e676f6f676c652e636f6d000b000403000102000a00160014001d0017001e00190018010001010102010301040010000e000c02683208687474702f312e31001600000017000000310000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b0009080304030303020301002d00020101003300260024001d00207fe08226bdc4fb1715e477506b6afe8f3abe2d20daa1f8c78c5483f1a90a9b19001500af00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	tlsGoogle, err := hex.DecodeString(tlsGoogleHex)
	if err != nil {
		t.Fatalf("decode tls google hex: %v", err)
	}

	httpDomain, httpErr := sniffing.NewStreamSniffer(bytes.NewReader(httpRequest), 300*time.Millisecond).SniffTcp()
	tlsDomain, tlsErr := sniffing.NewStreamSniffer(bytes.NewReader(tlsGoogle), 300*time.Millisecond).SniffTcp()

	packet := sniffing.NewPacketSniffer([]byte("hello"), time.Second)
	copied := packet.Data()
	copied[0][0] = 'H'
	view := packet.DataView()
	copyDetached := string(view[0]) == "hello"
	_ = packet.Close()

	oversized := sniffing.NewPacketSniffer(nil, time.Second)
	oversized.AppendData(make([]byte, sniffing.PacketSnifferMaxBufferedBytes+1))
	_, oversizedErr := oversized.SniffUdp()

	return map[string]any{
		"name": "sniffing-basic",
		"source": []string{
			"component/sniffing/sniffing.go",
			"component/sniffing/sniffer.go",
			"component/sniffing/http.go",
			"component/sniffing/tls.go",
			"component/sniffing/quic.go",
		},
		"notes": "Stage 3 fixture fixes HTTP/TLS sniffing and packet sniffer buffer/cap behavior; QUIC cap is covered without requiring runtime QUIC decryption in Rust.",
		"cases": []any{
			map[string]any{
				"name":      "http-host-normalize-and-retain",
				"input_hex": hex.EncodeToString(httpRequest),
				"ok":        httpErr == nil,
				"domain":    httpDomain,
				"error":     errorString(httpErr),
			},
			map[string]any{
				"name":      "tls-google-sni",
				"input_hex": tlsGoogleHex,
				"ok":        tlsErr == nil,
				"domain":    tlsDomain,
				"error":     errorString(tlsErr),
			},
			map[string]any{
				"name":          "packet-data-detached-copy",
				"input":         "hello",
				"copy_detached": copyDetached,
				"data_view":     string(view[0]),
			},
			map[string]any{
				"name":         "packet-quic-buffer-cap",
				"append_size":  sniffing.PacketSnifferMaxBufferedBytes + 1,
				"need_more":    oversized.NeedMore(),
				"error":        errorString(oversizedErr),
				"is_sniff_err": sniffing.IsSniffingError(oversizedErr),
			},
		},
	}
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func BenchmarkRebuildStage2Config(b *testing.B) {
	example, err := os.ReadFile("example.dae")
	if err != nil {
		b.Fatalf("read example.dae: %v", err)
	}
	exampleText := string(example)

	b.Run("parser_example", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := config_parser.Parse(exampleText); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("schema_example", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sections, err := config_parser.Parse(exampleText)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := daeconfig.New(sections); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("include_merger", func(b *testing.B) {
		entry := stage2BenchmarkIncludeTree(b)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, _, err := daeconfig.NewMerger(entry).Merge(); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("marshal_roundtrip_example", func(b *testing.B) {
		root := b.TempDir()
		entry := filepath.Join(root, "example.dae")
		mustWriteFileMode(b, entry, example, 0640)
		sections, _, err := daeconfig.NewMerger(entry).Merge()
		if err != nil {
			b.Fatalf("merge example.dae: %v", err)
		}
		conf, err := daeconfig.New(sections)
		if err != nil {
			b.Fatalf("build example.dae: %v", err)
		}

		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			marshaled, err := conf.Marshal(2)
			if err != nil {
				b.Fatal(err)
			}
			roundtripSections, err := config_parser.Parse(string(marshaled))
			if err != nil {
				b.Fatal(err)
			}
			if _, err := daeconfig.New(roundtripSections); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkRebuildStage3RoutingGeodataSniffing(b *testing.B) {
	inputs := []string{"192.0.2.1", "2001:db8::1", "2001:db8::/48"}
	prefixParser := routing.IpParserFactory(func(_ *config_parser.Function, cidrs []netip.Prefix, _ *routing.Outbound) error {
		if len(cidrs) != 3 {
			b.Fatalf("unexpected prefix count: %d", len(cidrs))
		}
		return nil
	})
	prefixFunction := &config_parser.Function{Name: "ip"}
	benchLog := logrus.New()

	domainMatcher := domain_matcher.NewAhocorasickSlimtrie(logrus.New(), 96)
	domainMatcher.AddSet(0, []string{"example.com"}, consts.RoutingDomainKey_Suffix)
	domainMatcher.AddSet(1, []string{".child.example.com"}, consts.RoutingDomainKey_Suffix)
	domainMatcher.AddSet(31, []string{"cdn"}, consts.RoutingDomainKey_Keyword)
	domainMatcher.AddSet(32, []string{"exact.example.org"}, consts.RoutingDomainKey_Full)
	domainMatcher.AddSet(63, []string{`^api[0-9]+\.example\.net$`}, consts.RoutingDomainKey_Regex)
	if err := domainMatcher.Build(); err != nil {
		b.Fatalf("build domain matcher: %v", err)
	}

	geoipBytes := mustMarshalProto(b, &geodata.GeoIPList{Entry: []*geodata.GeoIP{
		{
			CountryCode: "CN",
			Cidr: []*geodata.CIDR{
				{Ip: []byte{203, 0, 113, 0}, Prefix: 24},
				{Ip: netip.MustParseAddr("2001:db8::").AsSlice(), Prefix: 32},
			},
		},
		{
			CountryCode: "US",
			Cidr: []*geodata.CIDR{
				{Ip: []byte{198, 51, 100, 0}, Prefix: 24},
			},
		},
	}})
	geoipPath := filepath.Join(b.TempDir(), "geoip.dat")
	mustWriteFileMode(b, geoipPath, geoipBytes, 0640)

	httpRequest := []byte("GET /path HTTP/1.1\r\nHost: Example.COM:443\r\nUser-Agent: dae\r\n\r\n")

	b.Run("routing_prefix_parse", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := prefixParser(benchLog, prefixFunction, "", inputs, &routing.Outbound{Name: "direct"}); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("domain_matcher_bitmap", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if got := domainMatcher.MatchDomainBitmap("API12.EXAMPLE.NET"); len(got) != 3 || got[1] != 0x80000000 {
				b.Fatalf("unexpected bitmap: %v", got)
			}
		}
	})

	b.Run("geodata_streaming_geoip_hit", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			entry, err := geodata.Decode(geoipPath, "cn")
			if err != nil {
				b.Fatal(err)
			}
			if len(entry) == 0 {
				b.Fatal("empty geodata entry")
			}
		}
	})

	b.Run("sniffing_http_host", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			domain, err := sniffing.NewStreamSniffer(bytes.NewReader(httpRequest), time.Second).SniffTcp()
			if err != nil {
				b.Fatal(err)
			}
			if domain != "example.com" {
				b.Fatalf("unexpected domain: %s", domain)
			}
		}
	})
}

func rebuildGoldenDnsCacheKey() any {
	inetA := dnsCacheKeyProjection("Example.COM", dnsmessage.TypeA, dnsmessage.ClassINET)
	inetAAAA := dnsCacheKeyProjection("example.com.", dnsmessage.TypeAAAA, dnsmessage.ClassINET)
	nonINETA := dnsCacheKeyProjection("example.com.", dnsmessage.TypeA, 3)
	return map[string]any{
		"name": "dns-cache-key-basic",
		"source": []string{
			"control/dns_control.go:newDnsCacheKey",
			"control/dns_control.go:parseDnsCacheKey",
			"control/dns_control_test.go:TestDnsCacheKeyIncludesQuestionTypeAndClass",
		},
		"notes": "DNS cache key must include canonical lowercase fqdn, qtype and qclass; legacy key keeps INET default.",
		"cases": []any{
			map[string]any{
				"name":              "inet-a",
				"qname":             "Example.COM",
				"qtype":             dnsmessage.TypeA,
				"qclass":            dnsmessage.ClassINET,
				"key":               inetA,
				"structured":        inetA["string"],
				"legacy":            "example.com.1",
				"legacy_parse":      inetA,
				"structured_parse":  inetA,
				"canonical_lowered": "example.com.",
			},
			map[string]any{
				"name":   "inet-aaaa",
				"qname":  "example.com.",
				"qtype":  dnsmessage.TypeAAAA,
				"qclass": dnsmessage.ClassINET,
				"key":    inetAAAA,
			},
			map[string]any{
				"name":   "class-3-a",
				"qname":  "example.com.",
				"qtype":  dnsmessage.TypeA,
				"qclass": 3,
				"key":    nonINETA,
			},
		},
		"different": map[string]any{
			"a_vs_aaaa":         !reflect.DeepEqual(inetA, inetAAAA),
			"inet_vs_class_3":   !reflect.DeepEqual(inetA, nonINETA),
			"structured_format": "qname|qtype|qclass",
		},
	}
}

func dnsCacheKeyProjection(qname string, qtype uint16, qclass uint16) map[string]any {
	canonical := strings.ToLower(dnsmessage.CanonicalName(qname))
	return map[string]any{
		"qname":  canonical,
		"qtype":  qtype,
		"qclass": qclass,
		"string": canonical + "|" + intString(qtype) + "|" + intString(qclass),
	}
}

func rebuildGoldenDnsCacheTtlEvictionStats() any {
	now := int64(1700000000)
	return map[string]any{
		"name": "dns-cache-ttl-eviction-stats",
		"source": []string{
			"control/dns_control.go:NormalizeAndCacheDnsResp_",
			"control/dns_control.go:LookupDnsRespCache",
			"control/dns_control.go:evictDnsCacheEntriesLocked",
			"control/dns_control_test.go:TestNormalizeAndCacheDnsRespUsesQuestionClassInCacheKey",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:31.4.2",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:31.4.3",
		},
		"notes":       "fixed_domain_ttl affects client deadline only; original deadline is kept for internal routing lookup.",
		"now_unix":    now,
		"max_entries": 4096,
		"cases": []any{
			map[string]any{
				"name":                   "min-answer-ttl",
				"answer_ttls":            []int{300, 60},
				"effective_deadline":     now + 60,
				"original_deadline":      now + 60,
				"client_lookup_after_30": true,
				"client_lookup_after_61": false,
			},
			map[string]any{
				"name":               "fixed-domain-ttl",
				"host":               "example.com",
				"upstream_ttl":       60,
				"fixed_domain_ttl":   10,
				"effective_deadline": now + 10,
				"original_deadline":  now + 60,
			},
			map[string]any{
				"name":                      "fixed-domain-ttl-zero",
				"host":                      "example.com",
				"upstream_ttl":              60,
				"fixed_domain_ttl":          0,
				"effective_deadline":        now,
				"original_deadline":         now + 60,
				"client_lookup_after_now":   false,
				"internal_lookup_after_now": true,
				"map_entry_kept":            true,
			},
			map[string]any{
				"name":               "explicit-deadline-ignores-fixed-ttl",
				"host":               "upstream.example",
				"fixed_domain_ttl":   0,
				"explicit_deadline":  now + 24*60*60,
				"effective_deadline": now + 24*60*60,
				"original_deadline":  now + 24*60*60,
			},
		},
		"eviction": map[string]any{
			"capacity":        3,
			"existing":        []string{"oldest.example.", "middle.example.", "newest.example."},
			"deadlines":       []int64{now + 10, now + 20, now + 30},
			"insert":          "inserted.example.",
			"removed":         []string{"oldest.example."},
			"size_after":      3,
			"expired_removed": 0,
		},
		"stats_no_mutation": map[string]any{
			"live_entry_count":                   1,
			"expired_client_original_live_count": 1,
			"expired_and_original_expired_count": 1,
			"cache_stats_live":                   2,
			"remove_callback_called":             0,
			"map_size_after_cache_stats":         3,
		},
	}
}

func rebuildGoldenDnsPackedResponse(t *testing.T) any {
	t.Helper()

	req := new(dnsmessage.Msg)
	req.SetQuestion("example.com.", dnsmessage.TypeA)
	req.Id = 0
	resp := new(dnsmessage.Msg)
	resp.SetReply(req)
	resp.Answer = []dnsmessage.RR{newDnsFixtureA("example.com.", "1.2.3.4", 0)}
	packed := mustPackDnsMsg(t, resp)
	restored := append([]byte(nil), packed...)
	restored[0] = 0x43
	restored[1] = 0x21

	alias := dnsmessage.CanonicalName("alias.example.")
	target := dnsmessage.CanonicalName("target.example.")
	cnameReq := new(dnsmessage.Msg)
	cnameReq.SetQuestion(alias, dnsmessage.TypeA)
	cnameReq.Id = 0
	cnameResp := new(dnsmessage.Msg)
	cnameResp.SetReply(cnameReq)
	cnameResp.Answer = []dnsmessage.RR{
		&dnsmessage.CNAME{
			Hdr:    dnsmessage.RR_Header{Name: alias, Rrtype: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, Ttl: 60},
			Target: target,
		},
		newDnsFixtureA(target, "203.0.113.20", 60),
	}

	return map[string]any{
		"name": "dns-packed-response-basic",
		"source": []string{
			"control/dns_cache.go:FillPackedResponse",
			"control/dns_cache_restore_test.go:TestRestoreDnsCacheSnapshotPreservesPackedCNAMEAndQuestionDomainBitmap",
		},
		"notes": "Packed DNS cache responses store zero/old ID and restore caller request ID before returning.",
		"restore_request_id": map[string]any{
			"request_id":         0x4321,
			"packed_zero_id_hex": hex.EncodeToString(packed),
			"restored_hex":       hex.EncodeToString(restored),
			"restored_prefix":    hex.EncodeToString(restored[:2]),
		},
		"cname_restore": map[string]any{
			"alias":                  alias,
			"target":                 target,
			"packed_hex":             hex.EncodeToString(mustPackDnsMsg(t, cnameResp)),
			"answer_types":           []string{"CNAME", "A"},
			"target_ip":              "203.0.113.20",
			"include_target_ip":      true,
			"question_domain_bitmap": []uint32{0x40},
			"target_domain_bitmap":   []uint32{0x80},
		},
	}
}

func rebuildGoldenDnsValidation() any {
	return map[string]any{
		"name": "dns-validation-question-and-id",
		"source": []string{
			"control/dns_control.go:validateDnsResponseForRequest",
			"control/dns_control.go:formatDnsQuestion",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:31.4.5",
		},
		"notes": "DNS response validation checks response bit, optional ID equality and exact question qname/qtype/qclass.",
		"request": map[string]any{
			"id":     0x1111,
			"qname":  "example.com.",
			"qtype":  dnsmessage.TypeA,
			"qclass": dnsmessage.ClassINET,
		},
		"cases": []any{
			map[string]any{"name": "matching-question", "response_id": 0x1111, "questions": []any{dnsQuestionFixture("example.com.", dnsmessage.TypeA, dnsmessage.ClassINET)}, "require_id": true, "ok": true},
			map[string]any{"name": "missing-question", "response_id": 0x1111, "questions": []any{}, "require_id": true, "ok": false, "error": "dns response missing question"},
			map[string]any{"name": "mismatched-question", "response_id": 0x1111, "questions": []any{dnsQuestionFixture("other.example.", dnsmessage.TypeA, dnsmessage.ClassINET)}, "require_id": true, "ok": false, "error": "dns response question mismatch at index 0: got other.example. A class=1 want example.com. A class=1"},
			map[string]any{"name": "mismatched-id-required", "response_id": 0x2222, "questions": []any{dnsQuestionFixture("example.com.", dnsmessage.TypeA, dnsmessage.ClassINET)}, "require_id": true, "ok": false, "error": "dns response id mismatch: got 8738 want 4369"},
			map[string]any{"name": "mismatched-id-not-required", "response_id": 0x2222, "questions": []any{dnsQuestionFixture("example.com.", dnsmessage.TypeA, dnsmessage.ClassINET)}, "require_id": false, "ok": true},
		},
	}
}

func rebuildGoldenDnsDoh() any {
	small := []byte{0x12, 0x34, 0x56, 0x78}
	smallZero := dnsFixtureZeroID(small)
	large := append([]byte{0x12, 0x34}, bytes.Repeat([]byte{0xab}, 1024)...)
	largeZero := dnsFixtureZeroID(large)
	return map[string]any{
		"name": "dns-doh-get-post-validation",
		"source": []string{
			"control/dns.go:buildDoHRequest",
			"control/dns.go:validateDoHResponse",
			"control/dns_http_test.go",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:31.4.6",
		},
		"notes":                       "DoH request payload zeroes DNS ID; small payload uses GET query, large payload uses POST body.",
		"media_type":                  "application/dns-message",
		"get_max_encoded_query_bytes": 1024,
		"get_small_payload": map[string]any{
			"target":       "1.1.1.1:443",
			"hostname":     "dns.example.com",
			"path":         "/dns-query",
			"input_hex":    hex.EncodeToString(small),
			"zero_id_hex":  hex.EncodeToString(smallZero),
			"method":       "GET",
			"accept":       "application/dns-message",
			"content_type": "",
			"host":         "dns.example.com",
			"dns_query":    base64.RawURLEncoding.EncodeToString(smallZero),
			"url":          "https://1.1.1.1:443/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(smallZero),
		},
		"post_large_payload": map[string]any{
			"input_len":      len(large),
			"zero_id_prefix": hex.EncodeToString(largeZero[:4]),
			"method":         "POST",
			"accept":         "application/dns-message",
			"content_type":   "application/dns-message",
			"query_has_dns":  false,
			"body_len":       len(largeZero),
		},
		"validation": []any{
			map[string]any{"name": "bad-status", "status": "502 Bad Gateway", "content_type": "application/dns-message", "ok": false, "error": "doh server returned status 502 Bad Gateway", "status_failure_delta": 1},
			map[string]any{"name": "bad-content-type", "status": "200 OK", "content_type": "text/html; charset=utf-8", "ok": false, "error": `unexpected doh content-type "text/html; charset=utf-8"`, "content_type_failure_delta": 1},
			map[string]any{"name": "content-type-with-params", "status": "200 OK", "content_type": "application/dns-message; charset=binary", "ok": true},
			map[string]any{"name": "invalid-content-type-byte", "status": "200 OK", "content_type_hex": "7f", "ok": false, "error_contains": "invalid doh content-type"},
		},
	}
}

func rebuildGoldenDnsNetutils() any {
	return map[string]any{
		"name": "dns-netutils-basic",
		"source": []string{
			"common/netutils/dns.go:ResolveNetip",
			"common/netutils/dns_test.go",
			"control/dns.go:doUDPForwardDNS",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:31.4.7",
		},
		"notes": "TCP DNS reads length-prefixed full response; UDP uses PacketConn WriteTo/ReadFrom and retries timeout.",
		"tcp_full_read_one_byte_chunks": map[string]any{
			"network":     "tcp",
			"dns":         "1.1.1.1:53",
			"host":        "example.com",
			"qtype":       dnsmessage.TypeA,
			"chunk_bytes": 1,
			"answers":     []string{"1.2.3.4"},
		},
		"udp_packet_conn_semantics": map[string]any{
			"network":      "udp",
			"dns":          "1.1.1.1:53",
			"host":         "example.com",
			"qtype":        dnsmessage.TypeA,
			"write_to":     "1.1.1.1:53",
			"stream_write": false,
			"stream_read":  false,
			"answers":      []string{"5.6.7.8"},
		},
		"udp_retry_counter": map[string]any{
			"first_read_timeout":  true,
			"second_read_ok":      true,
			"write_count":         2,
			"retry_counter_delta": 1,
		},
	}
}

func rebuildGoldenDnsUpstreamResolver() any {
	now := int64(100)
	return map[string]any{
		"name": "dns-upstream-resolver-refresh",
		"source": []string{
			"component/dns/upstream.go:UpstreamResolver.GetUpstream",
			"component/dns/upstream_test.go",
			"component/dns/upstream_stats.go",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:31.4.8",
		},
		"notes": "UpstreamResolver reuses cached pointer before refresh, refreshes after interval, keeps stale on failure, and deduplicates concurrent refresh.",
		"cache_before_refresh": map[string]any{
			"now":           now,
			"refresh_after": now + 600,
			"resolve_calls": 1,
			"same_pointer":  true,
		},
		"refresh_after_interval": map[string]any{
			"first_ip":       "1.1.1.1",
			"second_ip":      "1.1.1.2",
			"resolve_calls":  2,
			"callback_calls": 2,
			"same_pointer":   false,
		},
		"stale_on_failure": map[string]any{
			"first_ip":              "1.1.1.1",
			"resolve_calls":         2,
			"same_pointer":          true,
			"retry_deadline":        now + 120 + 30,
			"refresh_success_delta": 1,
			"refresh_failure_delta": 1,
			"stale_reuse_delta":     1,
		},
		"dedupe_concurrent_refresh": map[string]any{
			"callers":       2,
			"resolve_calls": 1,
			"same_pointer":  true,
		},
	}
}

func rebuildGoldenDnsResolveIp46Guard() any {
	return map[string]any{
		"name": "dns-resolve-ip46-asis-original-target-guard",
		"source": []string{
			"control/dns_control.go:ResolveIp46",
			"control/dns_control.go:handleWithResponseWriter_",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:31.4.9",
		},
		"notes":            "Synthetic DNS lookup must not use original traffic target when DNS request fallback is asis.",
		"request_fallback": "asis",
		"host":             "target.example",
		"ipv4":             "",
		"ipv6":             "",
		"error":            `dns request routing cannot use "asis" for synthetic resolver lookup; configure an explicit upstream instead`,
	}
}

func dnsQuestionFixture(qname string, qtype uint16, qclass uint16) map[string]any {
	return map[string]any{
		"qname":  strings.ToLower(dnsmessage.CanonicalName(qname)),
		"qtype":  qtype,
		"qclass": qclass,
	}
}

func newDnsFixtureA(qname string, ip string, ttl uint32) *dnsmessage.A {
	return &dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   dnsmessage.CanonicalName(qname),
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    ttl,
		},
		A: net.ParseIP(ip).To4(),
	}
}

func mustPackDnsMsg(t testing.TB, msg *dnsmessage.Msg) []byte {
	t.Helper()
	packed, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack dns msg: %v", err)
	}
	return packed
}

func dnsFixtureZeroID(data []byte) []byte {
	out := append([]byte(nil), data...)
	if len(out) >= 2 {
		out[0], out[1] = 0, 0
	}
	return out
}

func rebuildGoldenOutboundGroupFixed() any {
	return map[string]any{
		"name": "outbound-group-fixed",
		"source": []string{
			"component/outbound/dialer_group.go:DialerGroup.Select",
			"component/outbound/dialer_group_test.go:TestDialerGroup_Select_Fixed",
		},
		"notes": "fixed policy selects by index and does not require alive state.",
		"policy": map[string]any{
			"name":        string(consts.DialerSelectionPolicy_Fixed),
			"fixed_index": 1,
		},
		"dialers": []string{"dialer0", "dialer1"},
		"cases": []any{
			map[string]any{"fixed_index": 1, "want_index": 1, "select_count": 10},
			map[string]any{"fixed_index": 0, "want_index": 0, "select_count": 10},
		},
		"requires_alive_state": false,
	}
}

func rebuildGoldenOutboundGroupMinLastLatency() any {
	return map[string]any{
		"name": "outbound-group-min-last-latency",
		"source": []string{
			"component/outbound/dialer_group.go:DialerGroup.Select",
			"component/outbound/dialer/alive_dialer_set.go:NotifyLatencyChange",
			"component/outbound/dialer_group_test.go:TestDialerGroup_Select_MinLastLatency",
		},
		"policy": string(consts.DialerSelectionPolicy_MinLastLatency),
		"cases": []any{
			map[string]any{
				"name":              "selects-fastest-alive-dialer",
				"latency_ms":        []int{200, 100, 300, 150},
				"alive":             []bool{true, true, true, true},
				"want_index":        1,
				"want_latency_ms":   100,
				"dead_fast_ignored": false,
			},
			map[string]any{
				"name":              "ignores-faster-dead-dialer",
				"latency_ms":        []int{50, 300, 120, 250},
				"alive":             []bool{false, true, true, true},
				"want_index":        2,
				"want_latency_ms":   120,
				"dead_fast_ignored": true,
			},
			map[string]any{
				"name":            "handles-alive-state-transitions",
				"latency_ms":      []int{400, 220, 180, 190},
				"alive":           []bool{true, false, true, true},
				"want_index":      2,
				"want_latency_ms": 180,
			},
		},
	}
}

func rebuildGoldenOutboundGroupMinAvg10() any {
	return map[string]any{
		"name": "outbound-group-min-avg10",
		"source": []string{
			"component/outbound/dialer_group_test.go:TestDialerGroup_Select_MinAverage10Latencies",
			"component/outbound/dialer/latencies_n.go",
		},
		"policy": string(consts.DialerSelectionPolicy_MinAverage10Latencies),
		"cases": []any{
			map[string]any{
				"name":            "uses-latency-ring-average",
				"dialer0_ms":      []int{300, 300, 300},
				"dialer1_ms":      []int{100, 100, 100},
				"want_index":      1,
				"want_latency_ms": 100,
			},
		},
	}
}

func rebuildGoldenOutboundGroupMinMovingAvg() any {
	return map[string]any{
		"name": "outbound-group-min-moving-avg",
		"source": []string{
			"component/outbound/dialer/lazy_state_test.go:TestAliveDialerSetMinMovingAverageUsesMovingAverage",
			"component/outbound/dialer/alive_dialer_set.go:NotifyLatencyChange",
		},
		"policy": string(consts.DialerSelectionPolicy_MinMovingAverageLatencies),
		"cases": []any{
			map[string]any{
				"name":            "selects-lowest-moving-average",
				"moving_avg_ms":   []int{400, 120},
				"want_index":      1,
				"want_latency_ms": 120,
			},
			map[string]any{
				"name":            "current-best-worsens-and-reselects",
				"moving_avg_ms":   []int{400, 800},
				"want_index":      0,
				"want_latency_ms": 400,
			},
		},
		"moving_average_first_success_ms": map[string]any{
			"input_latency_ms": 100,
			"stored_ms":        50,
			"notes":            "Go collection starts from 0 and updates as (old + latency) / 2.",
		},
	}
}

func rebuildGoldenOutboundGroupRandomAlive() any {
	return map[string]any{
		"name": "outbound-group-random-alive",
		"source": []string{
			"component/outbound/dialer_group_test.go:TestDialerGroup_Select_Random",
			"component/outbound/dialer_group_test.go:TestDialerGroup_SetAlive",
		},
		"policy":                  string(consts.DialerSelectionPolicy_Random),
		"dialer_count":            5,
		"selection_attempts":      100,
		"want_total":              100,
		"dead_index":              3,
		"dead_selected_count":     0,
		"distribution_stable":     false,
		"requires_latency_state":  false,
		"requires_alive_state":    true,
		"random_from_alive_nodes": true,
	}
}

func rebuildGoldenOutboundGroupIpVersionFallback() any {
	return map[string]any{
		"name": "outbound-group-ipversion-fallback-no-mutation",
		"source": []string{
			"component/outbound/dialer_group.go:DialerGroup.Select",
			"component/outbound/dialer_group_test.go:TestDialerGroup_Select_DoesNotMutateNetworkTypeOnFallback",
		},
		"policy":              string(consts.DialerSelectionPolicy_Random),
		"input":               outboundNetworkTypeFixture(consts.L4ProtoStr_TCP, consts.IpVersionStr_4, false),
		"fallback":            outboundNetworkTypeFixture(consts.L4ProtoStr_TCP, consts.IpVersionStr_6, false),
		"ipv4_alive":          false,
		"ipv6_alive":          true,
		"strict_ip_version":   false,
		"select_ok":           true,
		"input_after_select":  outboundNetworkTypeFixture(consts.L4ProtoStr_TCP, consts.IpVersionStr_4, false),
		"must_not_mutate_arg": true,
	}
}

func rebuildGoldenOutboundFilterNameSubtag() any {
	return map[string]any{
		"name": "outbound-filter-name-and-subscription-tag",
		"source": []string{
			"component/outbound/filter.go:DialerSet.FilterAndAnnotate",
			"component/outbound/filter_test.go:TestDialerSetFilterAndAnnotateMatchesCompiledFilters",
			"component/outbound/dialer/annotation.go:NewAnnotation",
		},
		"nodes": []any{
			map[string]any{"name": "HK-Netflix", "subscription_tag": "premium-sub"},
			map[string]any{"name": "JP-Game", "subscription_tag": "game-sub"},
			map[string]any{"name": "SG-Standard", "subscription_tag": "standard-sub"},
			map[string]any{"name": "US-Backup", "subscription_tag": "backup-sub"},
		},
		"filter_groups": []any{
			map[string]any{
				"filters": []any{
					map[string]any{"input": "name", "key": "regex", "value": "^(HK|JP)-"},
					map[string]any{"input": "subtag", "key": "regex", "value": "premium|game"},
				},
				"annotation": map[string]any{"add_latency_ms": 10},
			},
			map[string]any{
				"filters": []any{
					map[string]any{"input": "name", "key": "keyword", "value": "Backup"},
				},
				"annotation": map[string]any{"add_latency_ms": 25},
			},
		},
		"match_semantics": "filter groups OR; functions in one group AND; params inside one function OR",
		"matched": []any{
			map[string]any{"name": "HK-Netflix", "subscription_tag": "premium-sub", "add_latency_ms": 10},
			map[string]any{"name": "JP-Game", "subscription_tag": "game-sub", "add_latency_ms": 10},
			map[string]any{"name": "US-Backup", "subscription_tag": "backup-sub", "add_latency_ms": 25},
		},
		"unmatched": []string{"SG-Standard"},
	}
}

func rebuildGoldenOutboundFilterBadRegex() any {
	return map[string]any{
		"name": "outbound-filter-bad-regex",
		"source": []string{
			"component/outbound/filter_test.go:TestDialerSetFilterAndAnnotateBadRegex",
			"component/outbound/filter_test.go:TestDialerSetFilterAndAnnotateEmptySetDoesNotCompileFilters",
		},
		"bad_regex": "[",
		"cases": []any{
			map[string]any{
				"name":         "non-empty-dialer-set",
				"dialer_count": 1,
				"ok":           false,
				"error_prefix": "bad regexp in filter",
			},
			map[string]any{
				"name":         "empty-dialer-set",
				"dialer_count": 0,
				"ok":           true,
				"notes":        "empty set keeps historical lenient behavior and does not compile filters",
			},
		},
	}
}

func rebuildGoldenOutboundDialerLazyState() any {
	return map[string]any{
		"name": "outbound-dialer-lazy-state",
		"source": []string{
			"component/outbound/dialer/lazy_state_test.go:TestNewDialerLazilyAllocatesHealthState",
			"component/outbound/dialer/connectivity_check.go",
		},
		"new_dialer": map[string]any{
			"probe_http_client_nil":    true,
			"probe_http_transport_nil": true,
			"collections_allocated":    0,
			"alive_sets":               0,
		},
		"last_latency_snapshot": map[string]any{
			"latency_ms":       0,
			"alive":            true,
			"checked_at_zero":  true,
			"ok":               false,
			"alloc_collection": false,
		},
		"must_get_alive": map[string]any{
			"default_alive":    true,
			"alloc_collection": false,
			"missing_is_alive": true,
			"network_type":     outboundNetworkTypeFixture(consts.L4ProtoStr_TCP, consts.IpVersionStr_4, false),
		},
		"must_get_latencies10": map[string]any{
			"alloc_collection": true,
			"capacity":         10,
		},
		"probe_http_client": map[string]any{
			"first_use_creates": true,
			"second_use_reuses": true,
		},
	}
}

func rebuildGoldenOutboundAliveRandomSkipsLatency() any {
	return map[string]any{
		"name": "outbound-alive-set-random-skips-latency-state",
		"source": []string{
			"component/outbound/dialer/lazy_state_test.go:TestAliveDialerSetRandomSkipsLatencyState",
			"component/outbound/dialer/alive_dialer_set.go:NewAliveDialerSet",
		},
		"policy":                        string(consts.DialerSelectionPolicy_Random),
		"dialer_to_latency_allocated":   false,
		"latency_offset_allocated":      false,
		"initial_alive_count":           2,
		"after_dead_index":              0,
		"want_remaining_selected_index": 1,
	}
}

func rebuildGoldenOutboundAliveLatencyOffsetSparse() any {
	return map[string]any{
		"name": "outbound-alive-set-latency-offset-sparse",
		"source": []string{
			"component/outbound/dialer/lazy_state_test.go:TestAliveDialerSetLatencyOffsetsAreSparse",
			"component/outbound/dialer/alive_dialer_set.go:latencyOffset",
		},
		"policy":                          string(consts.DialerSelectionPolicy_MinLastLatency),
		"annotations_add_latency_ms":      []int{0, 50},
		"latency_offset_entries":          1,
		"zero_offset_stored":              false,
		"raw_latency_ms":                  []int{100, 100},
		"want_index":                      0,
		"want_sorting_latency_ms":         100,
		"offset_affects_sorting_only":     true,
		"raw_latency_must_not_be_mutated": true,
	}
}

func rebuildGoldenOutboundDirectInjectedResolver() any {
	return map[string]any{
		"name": "outbound-direct-injected-resolver",
		"source": []string{
			"component/outbound/dialer/direct.go:NewDirectDialer",
			"component/outbound/dialer/direct_test.go",
		},
		"cases": []any{
			map[string]any{
				"name":              "symmetric-prefers-resolver-dialer",
				"fullcone":          false,
				"injected":          "ResolverDialer",
				"selected":          "ResolverDialer",
				"property_name":     "direct",
				"fallback_possible": true,
			},
			map[string]any{
				"name":              "fullcone-prefers-fullcone-resolver-dialer",
				"fullcone":          true,
				"injected":          "ResolverFullconeDialer",
				"selected":          "ResolverFullconeDialer",
				"property_name":     "direct",
				"fallback_possible": true,
			},
			map[string]any{
				"name":                  "globals-unset-still-builds-fallback",
				"global_direct_nil":     true,
				"symmetric_fallback_ok": true,
				"fullcone_fallback_ok":  true,
			},
		},
	}
}

func rebuildGoldenOutboundProtocolSS2022() any {
	return map[string]any{
		"name": "outbound-protocol-ss2022-no-global-direct-dependency",
		"source": []string{
			"component/outbound/dialer/direct_test.go:TestNewFromLinkSS2022DoesNotDependOnGlobalDirectDialer",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26",
		},
		"link":                  "ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==@example.com:443#node",
		"global_direct_nil":     true,
		"new_from_link_ok":      true,
		"parent_dialer_non_nil": true,
		"adapter_mode":          "bridge-or-stub-until-native-protocol-rewrite",
	}
}

func rebuildGoldenOutboundGroupOverrideCloneProfile() any {
	return map[string]any{
		"name": "outbound-group-override-clone-profile-key",
		"source": []string{
			"control/group_override_clone_cache.go",
			"control/group_override_clone_cache_test.go",
		},
		"same_base_equivalent_profile": map[string]any{
			"reuse_clone":               true,
			"created_clones":            1,
			"clone_keeps_first_profile": true,
			"clone_is_not_base_wrapper": true,
			"tcp_check_url":             []string{"https://check.example/generate_204"},
			"udp_check_dns":             []string{"8.8.8.8:53"},
			"check_interval_ms":         durationMillis(15 * time.Second),
			"check_tolerance_ms":        durationMillis(10 * time.Millisecond),
		},
		"different_profiles": []string{
			"check_interval",
			"udp_check_dns",
			"resolver_dialer_identity",
			"base_dialer_identity",
		},
		"string_slice_profile_key": []any{
			map[string]any{"name": "nil-vs-empty", "a": nil, "b": []string{}, "same": false},
			map[string]any{"name": "value-boundary", "a": []string{"ab", "c"}, "b": []string{"a", "bc"}, "same": false},
			map[string]any{"name": "empty-element-boundary", "a": []string{"", "a"}, "b": []string{"a", ""}, "same": false},
		},
		"profile_counts": map[string]any{
			"profile_count": 2,
			"shared_count":  2,
			"unique_count":  1,
		},
	}
}

func rebuildGoldenOutboundConnectivityMapDimensions() any {
	return map[string]any{
		"name": "outbound-connectivity-map-dimensions",
		"source": []string{
			"control/control_plane_core.go:outboundAliveChangeCallback",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:25.16",
		},
		"key_fields": []string{"outbound", "l4proto", "ipversion"},
		"dimensions": []any{
			outboundConnectivityKeyFixture(2, consts.L4ProtoStr_TCP, consts.IpVersionStr_4, true),
			outboundConnectivityKeyFixture(2, consts.L4ProtoStr_TCP, consts.IpVersionStr_6, true),
			outboundConnectivityKeyFixture(2, consts.L4ProtoStr_UDP, consts.IpVersionStr_4, true),
			outboundConnectivityKeyFixture(2, consts.L4ProtoStr_UDP, consts.IpVersionStr_6, true),
		},
		"init_callback": map[string]any{
			"dryrun":       true,
			"still_writes": true,
			"value":        1,
		},
		"non_init_dryrun": map[string]any{
			"writes": false,
		},
		"alive_false_value":       0,
		"udp_53_kernel_exception": true,
	}
}

func rebuildGoldenOutboundLinkParserCompatibility() any {
	return map[string]any{
		"name": "outbound-link-parser-compatibility-matrix",
		"source": []string{
			"component/outbound/dialer/register.go",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26",
		},
		"notes":           "Stage 5 records compatibility and bridge/stub boundaries; full native protocol rewrite remains deferred.",
		"chain_separator": "->",
		"cases": []any{
			map[string]any{
				"name":         "direct",
				"link":         "direct://",
				"scheme":       "direct",
				"ok":           true,
				"adapter_mode": "native-boundary",
			},
			map[string]any{
				"name":         "block",
				"link":         "block://",
				"scheme":       "block",
				"ok":           true,
				"adapter_mode": "native-boundary",
			},
			map[string]any{
				"name":                  "ss2022",
				"link":                  "ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==@example.com:443#node",
				"scheme":                "ss",
				"protocol":              "shadowsocks-2022",
				"ok":                    true,
				"parent_dialer_non_nil": true,
				"adapter_mode":          "bridge-or-stub",
			},
			map[string]any{
				"name":         "chain",
				"link":         "socks5://127.0.0.1:1080 -> ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==@example.com:443#node",
				"chain_len":    2,
				"schemes":      []string{"socks5", "ss"},
				"ok":           true,
				"adapter_mode": "bridge-or-stub",
			},
			map[string]any{
				"name":  "bad-link",
				"link":  "not-a-link",
				"ok":    false,
				"error": "missing scheme",
			},
		},
	}
}

func outboundNetworkTypeFixture(l4 consts.L4ProtoStr, ip consts.IpVersionStr, isDNS bool) map[string]any {
	return map[string]any{
		"l4proto":    string(l4),
		"ipversion":  string(ip),
		"is_dns":     isDNS,
		"collection": outboundCollectionName(l4, ip, isDNS),
	}
}

func outboundConnectivityKeyFixture(outbound uint8, l4 consts.L4ProtoStr, ip consts.IpVersionStr, alive bool) map[string]any {
	value := 0
	if alive {
		value = 1
	}
	return map[string]any{
		"outbound":  outbound,
		"l4proto":   string(l4),
		"ipversion": string(ip),
		"value":     value,
	}
}

func outboundCollectionName(l4 consts.L4ProtoStr, ip consts.IpVersionStr, isDNS bool) string {
	if isDNS {
		return "dns_" + string(l4) + string(ip)
	}
	if l4 == consts.L4ProtoStr_UDP {
		return "dns_udp" + string(ip)
	}
	return "tcp" + string(ip)
}

func durationMillis(value time.Duration) int64 {
	return int64(value / time.Millisecond)
}

func intString[T ~uint16](value T) string {
	return fmt.Sprintf("%d", value)
}

func stage2BenchmarkIncludeTree(tb testing.TB) string {
	tb.Helper()

	root := tb.TempDir()
	mustMkdirAll(tb, filepath.Join(root, "config.d"))
	mustMkdirAll(tb, filepath.Join(root, "config.d", "dir.dae"))
	mustWriteFileMode(tb, filepath.Join(root, "entry.dae"), []byte(`
include {
    config.d/*
    missing/*.dae
}
global {
    log_level: info
}
routing {
    fallback: parent
}
`), 0640)
	mustWriteFileMode(tb, filepath.Join(root, "config.d", "child.dae"), []byte(`
include {
    nested.dae
}
global {
    log_level: debug
}
routing {
    domain(child.example) -> child
}
`), 0640)
	mustWriteFileMode(tb, filepath.Join(root, "nested.dae"), []byte(`
global {
    tcp_check_http_method: POST
}
node {
    nested: 'socks5://nested'
}
routing {
    domain(nested.example) -> nested
    fallback: nested
}
`), 0640)
	mustWriteFileMode(tb, filepath.Join(root, "config.d", "ignored.txt"), []byte(`global {}`), 0640)
	return filepath.Join(root, "entry.dae")
}

func rebuildGoldenConfigUtils(t *testing.T) any {
	t.Helper()

	return map[string]any{
		"name":   "config-utils-basic",
		"source": "common/utils.go:Base64UrlDecode,Base64StdDecode,EnsureFileInSubDir",
		"notes":  "Rust config utilities must keep Go base64 and path-safety compatibility for config parsing and file access.",
		"base64": map[string]any{
			"url": []any{
				base64Case("trim-and-padding", " aGk ", common.Base64UrlDecode),
				base64Case("missing-padding", "aGk", common.Base64UrlDecode),
				base64Case("invalid-return-original", "%%%", common.Base64UrlDecode),
			},
			"std": []any{
				base64Case("trim-and-padding", " aGk ", common.Base64StdDecode),
				base64Case("missing-padding", "aGk", common.Base64StdDecode),
				base64Case("invalid-return-original", "%%%", common.Base64StdDecode),
			},
		},
		"path_safety": rebuildGoldenPathSafety(t),
	}
}

func base64Case(name string, input string, decode func(string) (string, error)) map[string]any {
	got, err := decode(input)
	out := map[string]any{
		"name":  name,
		"input": input,
		"ok":    err == nil,
	}
	if err != nil {
		out["return"] = got
		out["error"] = err.Error()
		return out
	}
	out["decoded_hex"] = hex.EncodeToString([]byte(got))
	if utf8.ValidString(got) {
		out["decoded_text"] = got
	}
	return out
}

func rebuildGoldenPathSafety(t *testing.T) []any {
	t.Helper()

	base := t.TempDir()
	root := filepath.Join(base, "root")
	child := filepath.Join(root, "child")
	dotdotSibling := filepath.Join(root, "..sibling")
	outsideDir := filepath.Join(base, "outside")
	mustMkdirAll(t, child)
	mustMkdirAll(t, dotdotSibling)
	mustMkdirAll(t, outsideDir)
	mustWriteFile(t, filepath.Join(child, "file.txt"), []byte("child"))
	mustWriteFile(t, filepath.Join(dotdotSibling, "file.txt"), []byte("dotdot sibling"))
	mustWriteFile(t, filepath.Join(base, "outside.txt"), []byte("outside"))
	mustSymlink(t, outsideDir, filepath.Join(root, "linkdir"))
	mustSymlink(t, filepath.Join(base, "outside.txt"), filepath.Join(root, "linkfile"))

	missingRoot := filepath.Join(base, "missing-root")

	return []any{
		pathSafetyCase("normal-child-existing", filepath.Join(child, "file.txt"), root),
		pathSafetyCase("dotdot-sibling-name", filepath.Join(dotdotSibling, "file.txt"), root),
		pathSafetyCase("lexical-parent-escape", filepath.Join(root, "..", "outside.txt"), root),
		pathSafetyCase("missing-child-allowed", filepath.Join(root, "missing", "file.txt"), root),
		pathSafetyCase("missing-root-allowed", filepath.Join(missingRoot, "file.txt"), missingRoot),
		pathSafetyCase("symlink-dir-escape", filepath.Join(root, "linkdir", "file.txt"), root),
		pathSafetyCase("symlink-file-escape", filepath.Join(root, "linkfile"), root),
	}
}

func pathSafetyCase(name string, filePath string, dir string) map[string]any {
	err := common.EnsureFileInSubDir(filePath, dir)
	out := map[string]any{
		"name": name,
		"ok":   err == nil,
	}
	if err != nil {
		out["error"] = err.Error()
	}
	return out
}

func mustMkdirAll(t testing.TB, path string) {
	t.Helper()

	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func mustWriteFile(t testing.TB, path string, data []byte) {
	t.Helper()

	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustWriteFileMode(t testing.TB, path string, data []byte, perm os.FileMode) {
	t.Helper()

	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustSymlink(t testing.TB, oldname string, newname string) {
	t.Helper()

	if err := os.Symlink(oldname, newname); err != nil {
		t.Fatalf("symlink %s -> %s: %v", newname, oldname, err)
	}
}

func rebuildGoldenCommonUtils() any {
	return map[string]any{
		"name": "common-utils-basic",
		"source": []string{
			"common/utils.go:CloneStrings",
			"common/utils.go:ARangeU32",
			"common/utils.go:Deduplicate",
			"common/utils.go:StringSet",
			"common/utils.go:MapKeys",
			"common/utils.go:IsValidHttpMethod",
			"common/utils.go:SetValueHierarchicalMap",
			"common/utils.go:SetValueHierarchicalStruct",
			"common/utils.go:GetValueHierarchicalStruct",
		},
		"notes": "Rust config utilities must keep remaining pure common/utils behavior compatible before config parser migration.",
		"collections": map[string]any{
			"clone_strings": []any{
				cloneStringsCase("normal", []string{"a", "b"}),
				cloneStringsNilCase(),
			},
			"a_range_u32": []any{
				aRangeU32Case(0),
				aRangeU32Case(4),
			},
			"deduplicate": []any{
				deduplicateCase("preserve-first", []string{"a", "b", "a", "c", "b"}),
				deduplicateNilCase(),
			},
			"string_set": stringSetCase([]string{"b", "a", "b"}),
		},
		"map_keys": []any{
			mapKeysCase("string-map", map[string]int{"b": 2, "a": 1}),
			mapKeysCase("non-map", []string{"a"}),
			mapKeysCase("non-string-key", map[int]string{1: "a"}),
		},
		"http_methods": map[string]any{
			"valid":   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "COPY", "HEAD", "OPTIONS", "LINK", "UNLINK", "PURGE", "LOCK", "UNLOCK", "PROPFIND", "CONNECT", "TRACE"},
			"invalid": []string{"", "get", "connect", "BREW"},
		},
		"hierarchical_map": []any{
			hierarchicalMapCase("set-new-path", nil, "global.dial_mode", "domain"),
			hierarchicalMapCase("extend-existing-map", map[string]any{"global": map[string]any{"mptcp": true}}, "global.dial_mode", "domain"),
			hierarchicalMapCase("existing-non-map-error", map[string]any{"global": "not-map"}, "global.dial_mode", "domain"),
		},
		"hierarchical_struct": []any{
			hierarchicalStructCase("set-bool", "global.mptcp", "yes"),
			hierarchicalStructCase("set-duration", "global.duration", "1.5s"),
			hierarchicalStructCase("set-labels", "global.labels", "a,b"),
			hierarchicalStructCase("set-url", "global.url", "/relative/path"),
			hierarchicalStructCase("type-mismatch", "global.mptcp", "maybe"),
			hierarchicalStructCase("missing-child", "global.missing", "1"),
			hierarchicalStructCase("json-tag-ignored", "json_only", "1"),
			hierarchicalStructCase("case-sensitive", "Global.mptcp", "1"),
		},
	}
}

func cloneStringsCase(name string, input []string) map[string]any {
	got := common.CloneStrings(input)
	return map[string]any{
		"name":  name,
		"input": input,
		"want":  got,
	}
}

func cloneStringsNilCase() map[string]any {
	var input []string
	got := common.CloneStrings(input)
	return map[string]any{
		"name":  "nil",
		"input": input,
		"want":  got,
	}
}

func aRangeU32Case(n uint32) map[string]any {
	return map[string]any{
		"n":    n,
		"want": common.ARangeU32(n),
	}
}

func deduplicateCase(name string, input []string) map[string]any {
	return map[string]any{
		"name":  name,
		"input": input,
		"want":  common.Deduplicate(input),
	}
}

func deduplicateNilCase() map[string]any {
	var input []string
	return map[string]any{
		"name":  "nil",
		"input": input,
		"want":  common.Deduplicate(input),
	}
}

func stringSetCase(input []string) map[string]any {
	keys := make([]string, 0, len(input))
	for key := range common.StringSet(input) {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return map[string]any{
		"input": input,
		"keys":  keys,
	}
}

func mapKeysCase(name string, input any) map[string]any {
	keys, err := common.MapKeys(input)
	out := map[string]any{
		"name": name,
		"ok":   err == nil,
	}
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	sort.Strings(keys)
	out["keys_sorted"] = keys
	out["order"] = "unordered"
	return out
}

func hierarchicalMapCase(name string, initial map[string]any, key string, value any) map[string]any {
	if initial == nil {
		initial = map[string]any{}
	}
	err := common.SetValueHierarchicalMap(initial, key, value)
	out := map[string]any{
		"name":  name,
		"key":   key,
		"value": value,
		"ok":    err == nil,
	}
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	out["map"] = initial
	return out
}

type rebuildGoldenCommonStruct struct {
	Global   rebuildGoldenGlobalStruct `mapstructure:"global"`
	JsonOnly string                    `json:"json_only"`
}

type rebuildGoldenGlobalStruct struct {
	Mptcp    bool              `mapstructure:"mptcp"`
	Duration time.Duration     `mapstructure:"duration"`
	Labels   []string          `mapstructure:"labels"`
	URL      common.UrlOrEmpty `mapstructure:"url"`
}

func hierarchicalStructCase(name string, key string, value string) map[string]any {
	conf := &rebuildGoldenCommonStruct{}
	err := common.SetValueHierarchicalStruct(conf, key, value)
	out := map[string]any{
		"name":  name,
		"key":   key,
		"value": value,
		"ok":    err == nil,
	}
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	out["after"] = commonStructSnapshot(conf)
	return out
}

func commonStructSnapshot(conf *rebuildGoldenCommonStruct) map[string]any {
	var urlValue any
	if conf.Global.URL.Url != nil {
		urlValue = conf.Global.URL.Url.String()
	}
	return map[string]any{
		"global": map[string]any{
			"mptcp":    conf.Global.Mptcp,
			"duration": conf.Global.Duration.String(),
			"labels":   conf.Global.Labels,
			"url": map[string]any{
				"empty": conf.Global.URL.Empty,
				"url":   urlValue,
			},
		},
	}
}

func TestRebuildGoldenUpdateModeDoesNotRewriteByDefault(t *testing.T) {
	if os.Getenv(rebuildGoldenUpdateEnv) == "1" {
		t.Skip("update mode intentionally rewrites fixture files")
	}
	path := filepath.Join(t.TempDir(), "fixture.json")
	initial := []byte("{\"name\":\"kept\"}\n")
	if err := os.WriteFile(path, initial, 0644); err != nil {
		t.Fatalf("write temp fixture: %v", err)
	}

	writeOrCheckRebuildGolden(t, path, map[string]any{"name": "kept"})
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read temp fixture: %v", err)
	}
	if !bytes.Equal(got, initial) {
		t.Fatal("fixture changed without update env")
	}
}
