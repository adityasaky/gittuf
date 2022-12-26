package cmd

import (
	"fmt"

	"github.com/adityasaky/gittuf/gittuf"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the repository",
}

var verifyTrustedStatesCmd = &cobra.Command{
	Use:   "trusted-state <target> <stateA> <stateB>",
	Short: "Verifies if stateB can be trusted by stateA",
	Run:   runVerifyTrustedStates,
	Args:  cobra.ExactArgs(3),
}

var verifyStateCmd = &cobra.Command{
	Use:   "state",
	Short: "Verifies a target's hash matches signed TUF metadata",
	Run:   runVerifyState,
	Args:  cobra.ExactArgs(1),
}

func init() {
	verifyCmd.AddCommand(verifyStateCmd)
	verifyCmd.AddCommand(verifyTrustedStatesCmd)
	rootCmd.AddCommand(verifyCmd)
}

func runVerifyState(cmd *cobra.Command, args []string) {
	store, err := getGitTUFMetadataHandler()
	if err != nil {
		fmt.Println("Error:", err)
	}
	err = gittuf.VerifyState(store, args[0])
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("Target", args[0], "verified successfully!")
	}
}

func runVerifyTrustedStates(cmd *cobra.Command, args []string) {
	err := gittuf.VerifyTrustedStates(args[0], args[1], args[2])
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("Changes in state %s follow rules specified in state %s for %s!\n", args[2], args[1], args[0])
	}
}
