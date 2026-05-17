/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	daeconfig "github.com/daeuniverse/dae/config"
	daeengine "github.com/daeuniverse/dae/engine"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const cmdGoldenUpdateEnv = "DAE_UPDATE_REBUILD_GOLDEN"

func TestWriteCliGoldenFixtures(t *testing.T) {
	writeOrCheckCmdGolden(t, "../testdata/rebuild-golden/cli/surface/basic.json", rebuildGoldenCliSurface(t))
}

func BenchmarkCliValidateMinimalConfig(b *testing.B) {
	path := writeCmdConfig(b, "global {}\nrouting {}\n")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := daeengine.ReadConfigFile(path); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCliExportOutline(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = daeconfig.ExportOutlineJson(Version)
	}
}

func writeOrCheckCmdGolden(t *testing.T, path string, value any) {
	t.Helper()

	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	data = append(data, '\n')

	if os.Getenv(cmdGoldenUpdateEnv) == "1" {
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
	if !cmdJSONEqual(want, data) {
		t.Fatalf("%s does not match generated golden; run %s=1 go test ./cmd -run TestWriteCliGoldenFixtures", path, cmdGoldenUpdateEnv)
	}
}

func cmdJSONEqual(a, b []byte) bool {
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

func rebuildGoldenCliSurface(t *testing.T) any {
	completionCases := make([]map[string]any, 0, 4)
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		out, err := getCompletion(shell, rootCmd)
		item := map[string]any{
			"shell": shell,
			"ok":    err == nil,
		}
		if err != nil {
			item["error"] = err.Error()
		} else {
			item["non_empty"] = len(out) > 0
			item["mentions_dae"] = strings.Contains(out, "dae")
		}
		completionCases = append(completionCases, item)
	}
	service := readCmdText(t, "../install/dae.service")

	return map[string]any{
		"name": "cli-surface-basic",
		"source": []string{
			"cmd/cmd.go",
			"cmd/run.go",
			"cmd/reload.go",
			"cmd/suspend.go",
			"cmd/validate.go",
			"cmd/export.go",
			"cmd/completion.go",
			"engine/helpers.go",
			"install/dae.service",
			"common/consts/reload.go",
		},
		"notes": "Rust CLI must preserve command names, visible flags, progress bytes, file paths, validate/export/completion surfaces, and reload/suspend abort path.",
		"paths": map[string]any{
			"pid_file":             PidFilePath,
			"signal_progress_file": SignalProgressFilePath,
			"abort_file":           AbortFile,
		},
		"reload_progress": map[string]any{
			"send":       string([]byte{consts.ReloadSend}),
			"processing": string([]byte{consts.ReloadProcessing}),
			"done":       string([]byte{consts.ReloadDone}),
			"error":      string([]byte{consts.ReloadError}),
		},
		"root": map[string]any{
			"use":                             rootCmd.Use,
			"short":                           rootCmd.Short,
			"completion_default_cmd_disabled": rootCmd.CompletionOptions.DisableDefaultCmd,
			"version_line_count":              len(strings.Split(rootCmd.Version, "\n")),
			"version_contains_go_runtime":     strings.Contains(rootCmd.Version, "go runtime "),
			"version_contains_agpl":           strings.Contains(rootCmd.Version, "AGPLv3"),
		},
		"commands":         projectCommands(rootCmd),
		"completion_cases": completionCases,
		"validate": map[string]any{
			"requires_config_message": `Argument "--config" or "-c" is required but not provided.`,
			"does_not_start_runtime":  true,
			"read_config_function":    "engine.ReadConfigFile",
			"systemd_exec_start_pre":  serviceLine(service, "ExecStartPre="),
			"systemd_uses_validate":   strings.Contains(service, "ExecStartPre=/usr/bin/dae validate -c /etc/dae/config.dae"),
			"cases": []map[string]any{
				rebuildGoldenValidateCase(t, "minimal-valid", "global {}\nrouting {}\n"),
				rebuildGoldenValidateCase(t, "syntax-error", "global {\n"),
			},
		},
		"export": map[string]any{
			"outline_command":         "export outline",
			"outline_function":        "config.ExportOutlineJson",
			"stdout_trailing_newline": true,
			"outline_summary":         rebuildGoldenExportOutlineSummary(t),
		},
	}
}

func rebuildGoldenValidateCase(t *testing.T, name, content string) map[string]any {
	t.Helper()
	path := writeCmdConfig(t, content)
	_, includes, err := daeengine.ReadConfigFile(path)
	item := map[string]any{
		"name":          name,
		"ok":            err == nil,
		"stdout_on_ok":  "",
		"exit_on_error": 1,
	}
	if err != nil {
		item["error_contains"] = stableValidateError(err.Error())
	} else {
		item["include_count"] = len(includes)
	}
	return item
}

func writeCmdConfig(tb testing.TB, content string) string {
	tb.Helper()
	dir := tb.TempDir()
	path := filepath.Join(dir, "config.dae")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		tb.Fatalf("write config fixture: %v", err)
	}
	return path
}

func stableValidateError(message string) string {
	switch {
	case strings.Contains(message, "unexpected EOF"):
		return "unexpected EOF"
	case strings.Contains(message, "syntax error"):
		return "syntax error"
	case strings.Contains(message, "no viable alternative at input"):
		return "no viable alternative at input"
	default:
		return message
	}
}

func rebuildGoldenExportOutlineSummary(t *testing.T) map[string]any {
	t.Helper()
	outlineJSON := daeconfig.ExportOutlineJson(Version)
	var outline struct {
		Version   string   `json:"version"`
		Leaves    []string `json:"leaves"`
		Structure []struct {
			Mapping  string `json:"mapping"`
			Required bool   `json:"required"`
		} `json:"structure"`
	}
	if err := json.Unmarshal([]byte(outlineJSON), &outline); err != nil {
		t.Fatalf("unmarshal outline json: %v", err)
	}
	sections := make([]string, 0, len(outline.Structure))
	required := make([]string, 0)
	for _, section := range outline.Structure {
		sections = append(sections, section.Mapping)
		if section.Required {
			required = append(required, section.Mapping)
		}
	}
	sum := sha256.Sum256([]byte(outlineJSON))
	return map[string]any{
		"version":          outline.Version,
		"sha256":           hex.EncodeToString(sum[:]),
		"leaf_count":       len(outline.Leaves),
		"section_count":    len(outline.Structure),
		"sections":         sections,
		"required":         required,
		"contains_global":  containsString(sections, "global"),
		"contains_routing": containsString(sections, "routing"),
	}
}

func projectCommands(root *cobra.Command) []map[string]any {
	commands := make([]map[string]any, 0, len(root.Commands()))
	for _, command := range root.Commands() {
		item := map[string]any{
			"name":       command.Name(),
			"use":        command.Use,
			"short":      command.Short,
			"hidden":     command.Hidden,
			"valid_args": command.ValidArgs,
			"flags":      persistentFlagNames(command),
		}
		if len(command.Commands()) > 0 {
			item["children"] = projectCommands(command)
		}
		commands = append(commands, item)
	}
	sort.Slice(commands, func(i, j int) bool {
		return commands[i]["name"].(string) < commands[j]["name"].(string)
	})
	return commands
}

func persistentFlagNames(command *cobra.Command) []string {
	flags := make([]string, 0)
	command.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
		flags = append(flags, flag.Name)
	})
	sort.Strings(flags)
	return flags
}

func readCmdText(t *testing.T, path string) string {
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

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
