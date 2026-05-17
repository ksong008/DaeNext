/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const cmdGoldenUpdateEnv = "DAE_UPDATE_REBUILD_GOLDEN"

func TestWriteCliGoldenFixtures(t *testing.T) {
	writeOrCheckCmdGolden(t, "../testdata/rebuild-golden/cli/surface/basic.json", rebuildGoldenCliSurface(t))
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
		},
		"export": map[string]any{
			"outline_command": "export outline",
		},
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
