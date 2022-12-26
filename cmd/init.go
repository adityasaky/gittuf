package cmd

import (
	"encoding/json"

	"github.com/adityasaky/gittuf/gittuf"
	metadata "github.com/adityasaky/gittuf/internal/gittuf-metadata"
	"github.com/spf13/cobra"
	tufdata "github.com/theupdateframework/go-tuf/data"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a Git repository with TUF support",
	RunE:  runInit,
	// FIXME: Add validations using PreRunE
}

var (
	rootPrivKeyPaths    []string
	targetsPrivKeyPaths []string
	rootExpires         string
	targetsExpires      string
	rootThreshold       int
	targetsThreshold    int
)

func init() {
	rootCmd.AddCommand(initCmd)

	initCmd.Flags().StringArrayVarP(
		&rootPrivKeyPaths,
		"root-key",
		"",
		[]string{},
		"Path to private key that must be loaded for signing root metadata",
	)

	initCmd.Flags().StringArrayVarP(
		&targetsPrivKeyPaths,
		"targets-key",
		"",
		[]string{},
		"Path to private key that must be loaded for signing targets metadata",
	)

	initCmd.Flags().StringVarP(
		&rootExpires,
		"root-expires",
		"",
		"",
		"Expiry for root metadata in days",
	)

	initCmd.Flags().StringVarP(
		&targetsExpires,
		"targets-expires",
		"",
		"",
		"Expiry for targets metadata in days",
	)

	initCmd.Flags().IntVarP(
		&rootThreshold,
		"root-threshold",
		"",
		1,
		"Threshold of signatures needed for root role",
	)

	initCmd.Flags().IntVarP(
		&targetsThreshold,
		"targets-threshold",
		"",
		1,
		"Threshold of signatures needed for targets role",
	)
}

func runInit(cmd *cobra.Command, args []string) error {
	var rootPrivKeys []tufdata.PrivateKey
	for _, p := range rootPrivKeyPaths {
		rootPrivKey, err := gittuf.LoadEd25519PrivateKeyFromSslib(p)
		if err != nil {
			return err
		}
		rootPrivKeys = append(rootPrivKeys, rootPrivKey)
	}

	var targetsPrivKeys []tufdata.PrivateKey
	for _, p := range targetsPrivKeyPaths {
		targetsPrivKey, err := gittuf.LoadEd25519PrivateKeyFromSslib(p)
		if err != nil {
			return err
		}
		targetsPrivKeys = append(targetsPrivKeys, targetsPrivKey)
	}

	rootExpiresTime, err := parseExpires(rootExpires, "root")
	if err != nil {
		return err
	}

	targetsExpiresTime, err := parseExpires(targetsExpires, "targets")
	if err != nil {
		return err
	}

	var rootPublicKeys []tufdata.PublicKey
	for _, privKey := range rootPrivKeys {
		rootPubKey, err := gittuf.GetEd25519PublicKeyFromPrivateKey(&privKey)
		if err != nil {
			return err
		}
		rootPublicKeys = append(rootPublicKeys, rootPubKey)
	}

	var targetsPublicKeys []tufdata.PublicKey
	for _, privKey := range targetsPrivKeys {
		targetsPubKey, err := gittuf.GetEd25519PublicKeyFromPrivateKey(&privKey)
		if err != nil {
			return err
		}
		targetsPublicKeys = append(targetsPublicKeys, targetsPubKey)
	}

	roles, err := gittuf.Init(
		rootPrivKeys,
		rootExpiresTime,
		rootThreshold,
		rootPublicKeys,
		targetsPublicKeys,
		targetsPrivKeys,
		targetsExpiresTime,
		targetsThreshold,
		args...)
	if err != nil {
		return err
	}

	metadataContents := map[string][]byte{}

	for k, v := range roles {
		roleBytes, err := json.Marshal(v)
		if err != nil {
			return err
		}
		metadataContents[k] = roleBytes
	}

	// TODO: Should we undo git init if this call fails?
	store, err := metadata.InitMetadata(".", rootPublicKeys, metadataContents)
	if err != nil {
		return err
	}
	return store.State().Commit()
}
