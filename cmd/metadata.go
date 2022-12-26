package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/adityasaky/gittuf/gittuf"
	metadata "github.com/adityasaky/gittuf/internal/gittuf-metadata"
	"github.com/spf13/cobra"
)

var metadataCmd = &cobra.Command{
	Use:   "metadata",
	Short: "Inspect gittuf metadata",
}

var metadataInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize gittuf namespace",
	RunE:  runMetadataInit,
}

var metadataLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List current set of gittuf metadata",
	RunE:  runMetadataLs,
}

var metadataAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add specified file to gittuf namespace",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runMetadataAdd,
}

var metadataCatCmd = &cobra.Command{
	Use:   "cat",
	Short: "Print specified file on standard output",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runMetadataCat,
}

var metadataRmCmd = &cobra.Command{
	Use:   "rm",
	Short: "Remove specified files",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runMetadataRm,
}

func init() {
	metadataLsCmd.Flags().BoolVarP(
		&long,
		"long",
		"l",
		false,
		"Use a long listing format",
	)

	metadataCmd.AddCommand(metadataInitCmd)
	metadataCmd.AddCommand(metadataLsCmd)
	metadataCmd.AddCommand(metadataAddCmd)
	metadataCmd.AddCommand(metadataCatCmd)
	metadataCmd.AddCommand(metadataRmCmd)

	rootCmd.AddCommand(metadataCmd)
}

func runMetadataInit(cmd *cobra.Command, args []string) error {
	dir, err := gittuf.GetRepoRootDir()
	if err != nil {
		return err
	}
	return metadata.InitNamespace(dir)
}

func runMetadataLs(cmd *cobra.Command, args []string) error {
	store, err := getGitTUFMetadataHandler()
	if err != nil {
		return err
	}

	currentTree, err := store.State().GetTreeForNamespace(metadata.MetadataDir)
	if err != nil {
		return err
	}

	for _, e := range currentTree.Entries {
		if long {
			fmt.Println(e.Mode.String(), e.Hash.String(), e.Name)
		} else {
			fmt.Println(e.Name)
		}
	}
	return nil
}

func runMetadataAdd(cmd *cobra.Command, args []string) error {
	store, err := getGitTUFMetadataHandler()
	if err != nil {
		return err
	}

	metadata := map[string][]byte{}

	for _, n := range args {
		c, err := os.ReadFile(n)
		if err != nil {
			return err
		}
		metadata[n] = c
	}
	return store.State().StageAndCommitMultipleMetadata(metadata)
}

func runMetadataCat(cmd *cobra.Command, args []string) error {
	store, err := getGitTUFMetadataHandler()
	if err != nil {
		return err
	}

	for _, n := range args {
		n = strings.TrimSuffix(n, ".json")
		contents, err := store.State().GetCurrentMetadataString(n)
		if err != nil {
			return err
		}
		fmt.Println(contents)
	}

	return nil
}

func runMetadataRm(cmd *cobra.Command, args []string) error {
	store, err := getGitTUFMetadataHandler()
	if err != nil {
		return err
	}

	roles := []string{}

	for _, n := range args {
		roles = append(roles, strings.TrimSuffix(n, ".json"))
	}

	return store.State().RemoveMetadata(roles)
}
