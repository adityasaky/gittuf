package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	metadata "github.com/adityasaky/gittuf/internal/gittuf-metadata"
	"github.com/spf13/cobra"
	tufdata "github.com/theupdateframework/go-tuf/data"
)

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Inspect gittuf root keys",
}

var keysLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List current set of gittuf root keys",
	RunE:  runKeysLs,
}

var keysAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add specified key to gittuf namespace",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runKeysAdd,
}

var keysCatCmd = &cobra.Command{
	Use:   "cat",
	Short: "Print specified key on standard output",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runKeysCat,
}

var keysRmCmd = &cobra.Command{
	Use:   "rm",
	Short: "Remove specified keys",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runKeysRm,
}

func init() {
	keysLsCmd.Flags().BoolVarP(
		&long,
		"long",
		"l",
		false,
		"Use a long listing format",
	)

	keysCmd.AddCommand(keysLsCmd)
	keysCmd.AddCommand(keysAddCmd)
	keysCmd.AddCommand(keysCatCmd)
	keysCmd.AddCommand(keysRmCmd)

	rootCmd.AddCommand(keysCmd)
}

func runKeysLs(cmd *cobra.Command, args []string) error {
	store, err := getGitTUFMetadataHandler()
	if err != nil {
		return err
	}

	currentTree, err := store.State().GetTreeForNamespace(metadata.KeysDir)
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

func runKeysAdd(cmd *cobra.Command, args []string) error {
	store, err := getGitTUFMetadataHandler()
	if err != nil {
		return err
	}

	var keys []tufdata.PublicKey

	for _, n := range args {
		c, err := os.ReadFile(n)
		if err != nil {
			return err
		}
		var k tufdata.PublicKey
		err = json.Unmarshal(c, &k)
		if err != nil {
			return err
		}
		keys = append(keys, k)
	}

	return store.State().StageKeysAndCommit(keys)
}

func runKeysCat(cmd *cobra.Command, args []string) error {
	store, err := getGitTUFMetadataHandler()
	if err != nil {
		return err
	}

	for _, n := range args {
		n = strings.TrimSuffix(n, ".pub")
		key, err := store.State().GetRootKeyString(n)
		if err != nil {
			return err
		}
		fmt.Println(key)
	}

	return nil
}

func runKeysRm(cmd *cobra.Command, args []string) error {
	store, err := getGitTUFMetadataHandler()
	if err != nil {
		return err
	}

	keyIDs := []string{}

	for _, n := range args {
		keyIDs = append(keyIDs, strings.TrimSuffix(n, ".pub"))
	}

	return store.State().RemoveKeys(keyIDs)
}
