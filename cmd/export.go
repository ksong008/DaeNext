/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"os"

	"github.com/daeuniverse/dae/config"
	daeengine "github.com/daeuniverse/dae/engine"
	"github.com/spf13/cobra"
)

var (
	exportCmd = &cobra.Command{
		Use:   "export",
		Short: "To export some information for UI developers.",
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	exportOutlineCmd = &cobra.Command{
		Use:   "outline",
		Short: "To export config structure.",
		Run: func(cmd *cobra.Command, args []string) {
			if text, used, err := daeengine.RustConfigOptInExportOutline(Version); used {
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				fmt.Print(text)
				return
			}
			fmt.Println(config.ExportOutlineJson(Version))
		},
	}
)

func init() {
	rootCmd.AddCommand(exportCmd)
	exportCmd.AddCommand(exportOutlineCmd)
}
