package cmd

import (
	"encoding/json"

	"github.com/adityasaky/gittuf/gittuf"
	"github.com/adityasaky/gittuf/internal/gitstore"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	tufdata "github.com/theupdateframework/go-tuf/data"
)

var commitCmd = &cobra.Command{
	Use:   "commit",
	Short: "Creates a commit object",
	RunE:  runCommit,
	Args:  cobra.MinimumNArgs(1),
}

var (
	roleExpires string
)

func init() {
	rootCmd.AddCommand(commitCmd)

	commitCmd.Flags().StringArrayVarP(
		&roleKeyPaths,
		"role-key",
		"",
		[]string{},
		"Path to signing key for role",
	)

	commitCmd.Flags().StringVarP(
		&roleExpires,
		"role-expires",
		"",
		"",
		"Expiry for role metadata in days",
	)

}

func runCommit(cmd *cobra.Command, args []string) error {
	store, err := getGitStore()
	if err != nil {
		return err
	}
	state := store.State()

	remotes, err := store.Repository().Remotes()
	if err != nil {
		return err
	}
	if len(remotes) > 0 {
		err = state.FetchFromRemote(gitstore.DefaultRemote)
		if err != nil {
			return err
		}
	}

	var roleKeys []tufdata.PrivateKey
	if len(roleKeyPaths) > 0 {
		for _, k := range roleKeyPaths {
			logrus.Debug("Loading key from", k)
			privKey, err := gittuf.LoadEd25519PrivateKeyFromSslib(k)
			if err != nil {
				return err
			}
			roleKeys = append(roleKeys, privKey)
		}
	} else {
		userConfigPath, err := gittuf.FindConfigPath()
		if err != nil {
			return err
		}
		userConfig, err := gittuf.ReadConfig(userConfigPath)
		if err != nil {
			return err
		}
		roleKeys = append(roleKeys, userConfig.PrivateKey)
	}

	branchName, err := gittuf.GetRefNameForHEAD()
	if err != nil {
		return err
	}

	expires, err := parseExpires(roleExpires, "targets")
	if err != nil {
		return err
	}

	// TODO: should gittuf.Commit infer target name or should we do it here?
	newRoleMb, target, err := gittuf.Commit(state, branchName, roleKeys, expires, args...)
	if err != nil {
		return err
	}

	// All errors after this point should undo the commit

	newRoleBytes, err := json.Marshal(newRoleMb)
	if err != nil {
		return gittuf.UndoLastCommit(err)
	}

	err = state.StageMetadataAndCommit(branchName, newRoleBytes)
	if err != nil {
		return gittuf.UndoLastCommit(err)
	}

	err = store.UpdateTrustedState(target, state.Tip())
	if err != nil {
		return gittuf.UndoLastCommit(err)
	}

	// We always want to explicitly return nil and pass errors to UndoLastCommit
	return nil
}
