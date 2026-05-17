package main_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const productGoldenUpdateEnv = "DAE_UPDATE_REBUILD_GOLDEN"

func TestWriteProductGoldenFixtures(t *testing.T) {
	writeOrCheckProductGolden(t, "testdata/rebuild-golden/product/install/systemd.json", rebuildGoldenStage8Systemd(t))
	writeOrCheckProductGolden(t, "testdata/rebuild-golden/product/release/workflows.json", rebuildGoldenStage8ReleaseWorkflows(t))
	writeOrCheckProductGolden(t, "testdata/rebuild-golden/product/integration/daed_contract.json", rebuildGoldenStage8DaedContract())
	writeOrCheckProductGolden(t, "testdata/rebuild-golden/product/outbound/native_migration_contract.json", rebuildGoldenStage8OutboundNativeContract(t))
}

func writeOrCheckProductGolden(t *testing.T, path string, value any) {
	t.Helper()

	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	data = append(data, '\n')

	if os.Getenv(productGoldenUpdateEnv) == "1" {
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
	if !productJSONEqual(want, data) {
		t.Fatalf("%s does not match generated golden; run %s=1 go test . -run TestWriteProductGoldenFixtures", path, productGoldenUpdateEnv)
	}
}

func productJSONEqual(a, b []byte) bool {
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

func rebuildGoldenStage8Systemd(t *testing.T) any {
	t.Helper()
	service := readText(t, "install/dae.service")
	afterInstall := readText(t, "install/package_after_install.sh")
	afterRemove := readText(t, "install/package_after_remove.sh")
	return map[string]any{
		"name": "stage8-install-systemd-contract",
		"source": []string{
			"install/dae.service",
			"install/package_after_install.sh",
			"install/package_after_remove.sh",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:17.7",
		},
		"service": map[string]any{
			"type_notify":       strings.Contains(service, "Type=notify"),
			"user_root":         strings.Contains(service, "User=root"),
			"limit_nproc":       serviceLine(service, "LimitNPROC="),
			"limit_nofile":      serviceLine(service, "LimitNOFILE="),
			"exec_start_pre":    serviceLine(service, "ExecStartPre="),
			"exec_start":        serviceLine(service, "ExecStart="),
			"exec_reload":       serviceLine(service, "ExecReload="),
			"restart":           serviceLine(service, "Restart="),
			"timeout_start_sec": serviceLine(service, "TimeoutStartSec="),
			"after":             serviceLine(service, "After="),
			"wants":             serviceLine(service, "Wants="),
		},
		"package_hooks": map[string]any{
			"after_install_daemon_reload": strings.Contains(afterInstall, "systemctl daemon-reload"),
			"after_install_restart_active": strings.Contains(afterInstall, "systemctl restart dae.service"),
			"after_remove_daemon_reload":  strings.Contains(afterRemove, "systemctl daemon-reload"),
		},
		"rust_parity": map[string]any{
			"validate_exec_start_pre": true,
			"run_systemd_notify":      true,
			"reload_pid_progress":     true,
		},
	}
}

func rebuildGoldenStage8ReleaseWorkflows(t *testing.T) any {
	t.Helper()
	release := readText(t, ".github/workflows/release.yml")
	daenewRelease := readText(t, ".github/workflows/daenew-release.yml")
	seed := readText(t, ".github/workflows/seed-build.yml")
	friendlyRaw := readText(t, "install/friendly-filenames.json")
	var friendly map[string]map[string]string
	if err := json.Unmarshal([]byte(friendlyRaw), &friendly); err != nil {
		t.Fatalf("friendly filenames json: %v", err)
	}
	keys := make([]string, 0, len(friendly))
	for key := range friendly {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return map[string]any{
		"name": "stage8-release-workflow-contract",
		"source": []string{
			".github/workflows/release.yml",
			".github/workflows/daenew-release.yml",
			".github/workflows/seed-build.yml",
			"install/friendly-filenames.json",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:17.3-17.6",
		},
		"release": map[string]any{
			"prepare_tag_job":             strings.Contains(release, "prepare-tag:"),
			"checks_existing_tag_sha":     strings.Contains(release, "tag_sha=$(git rev-parse"),
			"update_tag_gate":             strings.Contains(release, "UPDATE_TAG"),
			"make_latest_input":           strings.Contains(release, "make_latest:"),
			"build_output_pkgdir":         strings.Contains(release, "OUTPUT=pkgdir/usr/bin/dae"),
			"installs_systemd_service":    strings.Contains(release, "install/dae.service"),
			"packages_deb_rpm_pacman":     strings.Contains(release, "for pkg_mgr in deb rpm") && strings.Contains(release, ".pkg.tar.zst"),
			"uploads_release_assets":      strings.Contains(release, "softprops/action-gh-release"),
		},
		"daenew_release": map[string]any{
			"default_ref":              "daenew",
			"default_make_latest_false": strings.Contains(daenewRelease, "default: false"),
			"update_tag_false":         strings.Contains(daenewRelease, "update_tag: false"),
		},
		"seed_build": map[string]any{
			"uses_friendly_filenames": strings.Contains(seed, "install/friendly-filenames.json"),
			"smoke_test_amd64_v1":     strings.Contains(seed, "--version"),
			"copies_service_example_geodata": strings.Contains(seed, "cp ./install/dae.service") && strings.Contains(seed, "geosite.dat"),
		},
		"friendly_keys": keys,
	}
}

func rebuildGoldenStage8DaedContract() any {
	return map[string]any{
		"name": "stage8-daed-daewing-contract",
		"source": []string{
			"testdata/rebuild-golden/engine/runtime_overview/basic.json",
			"testdata/rebuild-golden/engine/dry_runtime/reload_stop.json",
			"testdata/rebuild-golden/cli/surface/basic.json",
			"testdata/rebuild-golden/engine/route_aware/target.json",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:29",
		},
		"required_surfaces": []string{
			"RuntimeOverview JSON fields",
			"reload progress bytes and paths",
			"validate/export CLI surfaces",
			"API-only dry runtime reload/stop",
			"route-aware HTTP target",
			"node latency snapshots",
			"DNS observability counters",
		},
		"local_dae_contract_fixed": true,
		"cross_repo_write_scope":    "not in dae-local phase8 commit; dae-wing/daed must be validated in their repos before product rollout",
	}
}

func rebuildGoldenStage8OutboundNativeContract(t *testing.T) any {
	t.Helper()
	linkParser := readText(t, "testdata/rebuild-golden/outbound/link_parser/compatibility_matrix.json")
	return map[string]any{
		"name": "stage8-outbound-native-migration-contract",
		"source": []string{
			"testdata/rebuild-golden/outbound/link_parser/compatibility_matrix.json",
			"testdata/rebuild-golden/outbound/protocol/ss2022_no_global_direct_dependency.json",
			"DAEX_RUST_REBUILD_PLAN_2026-05-16.md:D-002",
		},
		"current_boundary_contains_native_direct_block": strings.Contains(linkParser, `"adapter_mode": "native-boundary"`),
		"current_boundary_contains_bridge_or_stub":      strings.Contains(linkParser, `"adapter_mode": "bridge-or-stub"`),
		"replacement_rule": "protocols must move one by one from bridge-or-stub to native with fixture and live connectivity evidence",
		"not_silent_complete": true,
		"minimum_before_replacing_default_path": []string{
			"link parser fixture",
			"protocol handshake fixture",
			"transport option fixture",
			"live connectivity smoke test",
			"Go/Rust benchmark or latency observation",
		},
	}
}

func readText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func serviceLine(text, prefix string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	return ""
}
