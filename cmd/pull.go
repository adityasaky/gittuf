package cmd

import (
	"github.com/adityasaky/gittuf/gittuf"
	"github.com/spf13/cobra"
)

var pullCmd = &cobra.Command{
	Use:   "pull",
	Short: "Pulls changes from specified remote",
	RunE:  runPull,
	Args:  cobra.ExactArgs(2),
}

func init() {
	rootCmd.AddCommand(pullCmd)
}

func runPull(cmd *cobra.Command, args []string) error {
	store, err := getGitTUFMetadataHandler()
	if err != nil {
		return err
	}
	return gittuf.Pull(store, args[0], args[1])
}
