package cmd

import (
	"encoding/json"

	"github.com/adityasaky/gittuf/gittuf"
	metadata "github.com/adityasaky/gittuf/internal/gittuf-metadata"
	"github.com/spf13/cobra"
	tufdata "github.com/theupdateframework/go-tuf/data"
)

var newRuleCmd = &cobra.Command{
	Use:   "new-rule",
	Short: "Add new branch protection rule",
	RunE:  runNewRule,
	// FIXME: Add validations using PreRunE
}

var (
	ruleName        string
	ruleThreshold   int
	ruleTerminating bool
	protectPaths    []string
	allowedKeyPaths []string
)

func init() {
	rootCmd.AddCommand(newRuleCmd)

	newRuleCmd.Flags().StringVarP(
		&role,
		"role",
		"",
		"targets",
		"Role to add rule to (default: top level targets)",
	)

	newRuleCmd.Flags().StringArrayVarP(
		&roleKeyPaths,
		"role-key",
		"",
		[]string{},
		"Path to signing key for role",
	)

	newRuleCmd.Flags().StringVarP(
		&ruleName,
		"rule-name",
		"",
		"",
		"Name of rule, used for delegation name",
	)

	newRuleCmd.Flags().IntVarP(
		&ruleThreshold,
		"rule-threshold",
		"",
		1,
		"Threshold of keys that must sign for the rule",
	)

	newRuleCmd.Flags().BoolVarP(
		&ruleTerminating,
		"rule-terminating",
		"",
		false,
		"Indicate of delegation for rule is terminating",
	)

	newRuleCmd.Flags().StringArrayVarP(
		&protectPaths,
		"protect-path",
		"",
		[]string{},
		"Path to protect",
	)

	newRuleCmd.Flags().StringArrayVarP(
		&allowedKeyPaths,
		"allow-key",
		"",
		[]string{},
		"Key allowed to sign metadata for protected paths",
	)
}

func runNewRule(cmd *cobra.Command, args []string) error {
	store, err := getGitTUFMetadataHandler()
	if err != nil {
		return err
	}
	state := store.State()

	err = state.FetchFromRemote(metadata.DefaultRemote)
	if err != nil {
		return err
	}

	var roleKeys []tufdata.PrivateKey
	for _, k := range roleKeyPaths {
		privKey, err := gittuf.LoadEd25519PrivateKeyFromSslib(k)
		if err != nil {
			return err
		}
		roleKeys = append(roleKeys, privKey)
	}

	var allowedKeys []tufdata.PublicKey
	for _, k := range allowedKeyPaths {
		pubKey, err := gittuf.LoadEd25519PublicKeyFromSslib(k)
		if err != nil {
			return err
		}
		allowedKeys = append(allowedKeys, pubKey)
	}

	newRoleMb, err := gittuf.NewRule(state, role, roleKeys, ruleName, ruleThreshold,
		ruleTerminating, protectPaths, allowedKeys)
	if err != nil {
		return err
	}

	newRoleBytes, err := json.Marshal(newRoleMb)
	if err != nil {
		return err
	}

	return state.StageMetadataAndCommit(role, newRoleBytes)
}
