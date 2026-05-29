package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
)

// versionCmd prints the SWAN-NG version and build commit.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print SWAN-NG version information",
	Run: func(cmd *cobra.Command, args []string) {
		v := version
		if v == "" {
			v = "dev"
		}

		c := commit
		if c == "" {
			c = "unknown"
		}

		fmt.Printf("swan-ng version %s (commit: %s)\n", v, c)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
