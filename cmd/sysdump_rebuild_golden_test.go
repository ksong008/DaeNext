package cmd

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestWriteSysdumpGoldenFixtures(t *testing.T) {
	writeOrCheckCmdGolden(t, "../testdata/rebuild-golden/sysdump/archive/path_safety.json", rebuildGoldenSysdumpArchivePathSafety(t))
	writeOrCheckCmdGolden(t, "../testdata/rebuild-golden/sysdump/archive/reject_escape.json", rebuildGoldenSysdumpArchiveRejectEscape(t))
	writeOrCheckCmdGolden(t, "../testdata/rebuild-golden/sysdump/enum_strings.json", rebuildGoldenSysdumpEnumStrings())
	writeOrCheckCmdGolden(t, "../testdata/rebuild-golden/sysdump/collector_best_effort.json", rebuildGoldenSysdumpCollectorBestEffort())
}

func rebuildGoldenSysdumpArchivePathSafety(t *testing.T) any {
	t.Helper()

	source := filepath.Join(t.TempDir(), "sysdump-source")
	if err := os.Mkdir(source, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "routing.txt"), []byte("route\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(source, "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "nested", "interfaces.txt"), []byte("if\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(source, "empty-dir"), 0755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "dae-sysdump.test.tar.gz")
	if err := createSysdumpArchive(source, target); err != nil {
		t.Fatalf("createSysdumpArchive: %v", err)
	}
	entries := readTarEntries(t, target)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i]["name"].(string) < entries[j]["name"].(string)
	})
	return map[string]any{
		"name": "sysdump-archive-path-safety",
		"source": []string{
			"cmd/sysdump.go",
		},
		"base_name": filepath.Base(source),
		"entries":   entries,
		"rules": map[string]any{
			"uses_relative_paths":     true,
			"slash_separator":         true,
			"non_regular_header_only": true,
		},
	}
}

func readTarEntries(t *testing.T, target string) []map[string]any {
	t.Helper()
	file, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gzipReader.Close()
	reader := tar.NewReader(gzipReader)
	var entries []map[string]any
	for {
		header, err := reader.Next()
		if err != nil {
			break
		}
		item := map[string]any{
			"name":     header.Name,
			"typeflag": int(header.Typeflag),
			"regular":  header.Typeflag == tar.TypeReg,
		}
		if header.Typeflag == tar.TypeReg {
			buf, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			item["content"] = string(buf)
		}
		entries = append(entries, item)
	}
	return entries
}

func rebuildGoldenSysdumpArchiveRejectEscape(t *testing.T) any {
	t.Helper()
	source := t.TempDir()
	target := filepath.Join(t.TempDir(), "dae-sysdump.reject.tar.gz")
	err := createSysdumpArchive(filepath.Join(source, "missing"), target)
	errText := ""
	if err != nil {
		errText = strings.ReplaceAll(err.Error(), filepath.Join(source, "missing"), "<source>/missing")
	}
	return map[string]any{
		"name": "sysdump-archive-reject-escape",
		"source": []string{
			"cmd/sysdump.go",
		},
		"unsafe_path_error_prefix": "unsafe sysdump archive path",
		"absolute_rel_rejected":    true,
		"dotdot_rel_rejected":      true,
		"walk_error_is_hard_error": err != nil,
		"missing_source_error":     errText,
	}
}

func rebuildGoldenSysdumpEnumStrings() any {
	return map[string]any{
		"name": "sysdump-enum-strings",
		"source": []string{
			"cmd/sysdump.go",
		},
		"scope": []map[string]any{
			{"value": unix.RT_SCOPE_UNIVERSE, "string": scopeToString(netlink.Scope(unix.RT_SCOPE_UNIVERSE))},
			{"value": unix.RT_SCOPE_SITE, "string": scopeToString(netlink.Scope(unix.RT_SCOPE_SITE))},
			{"value": unix.RT_SCOPE_LINK, "string": scopeToString(netlink.Scope(unix.RT_SCOPE_LINK))},
			{"value": unix.RT_SCOPE_HOST, "string": scopeToString(netlink.Scope(unix.RT_SCOPE_HOST))},
			{"value": unix.RT_SCOPE_NOWHERE, "string": scopeToString(netlink.Scope(unix.RT_SCOPE_NOWHERE))},
			{"value": 255, "string": scopeToString(netlink.Scope(255))},
		},
		"protocol": []map[string]any{
			{"value": unix.RTPROT_BABEL, "string": protocolToString(unix.RTPROT_BABEL)},
			{"value": unix.RTPROT_BGP, "string": protocolToString(unix.RTPROT_BGP)},
			{"value": unix.RTPROT_BIRD, "string": protocolToString(unix.RTPROT_BIRD)},
			{"value": unix.RTPROT_BOOT, "string": protocolToString(unix.RTPROT_BOOT)},
			{"value": unix.RTPROT_DHCP, "string": protocolToString(unix.RTPROT_DHCP)},
			{"value": unix.RTPROT_KERNEL, "string": protocolToString(unix.RTPROT_KERNEL)},
			{"value": unix.RTPROT_STATIC, "string": protocolToString(unix.RTPROT_STATIC)},
			{"value": unix.RTPROT_UNSPEC, "string": protocolToString(unix.RTPROT_UNSPEC)},
			{"value": 255, "string": protocolToString(255)},
		},
		"route_type": []map[string]any{
			{"value": unix.RTN_UNSPEC, "string": typeToString(unix.RTN_UNSPEC)},
			{"value": unix.RTN_UNICAST, "string": typeToString(unix.RTN_UNICAST)},
			{"value": unix.RTN_LOCAL, "string": typeToString(unix.RTN_LOCAL)},
			{"value": unix.RTN_BROADCAST, "string": typeToString(unix.RTN_BROADCAST)},
			{"value": unix.RTN_BLACKHOLE, "string": typeToString(unix.RTN_BLACKHOLE)},
			{"value": unix.RTN_UNREACHABLE, "string": typeToString(unix.RTN_UNREACHABLE)},
			{"value": unix.RTN_PROHIBIT, "string": typeToString(unix.RTN_PROHIBIT)},
			{"value": 255, "string": typeToString(255)},
		},
	}
}

func rebuildGoldenSysdumpCollectorBestEffort() any {
	return map[string]any{
		"name": "sysdump-collector-best-effort",
		"source": []string{
			"cmd/sysdump.go",
		},
		"collectors": []map[string]any{
			{"name": "routing", "output": "routing.txt", "failure": "print error and continue"},
			{"name": "interfaces", "output": "interfaces.txt", "failure": "print error and continue"},
			{"name": "sysctl", "output": "sysctl.txt", "failure": "print error and continue"},
			{"name": "nftables", "output": "nftables.txt", "failure": "print error and continue"},
			{"name": "iptables", "output": "iptables.txt", "failure": "print error and continue"},
			{"name": "ip6tables", "output": "ip6tables.txt", "failure": "print error and continue"},
		},
		"archive_failure_is_hard_error": true,
		"external_command_missing_rule": "print command error and continue collecting remaining sections",
	}
}

func BenchmarkRebuildStage8SysdumpEnumStrings(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = scopeToString(netlink.Scope(unix.RT_SCOPE_LINK))
		_ = protocolToString(unix.RTPROT_STATIC)
		_ = typeToString(unix.RTN_UNICAST)
	}
}
