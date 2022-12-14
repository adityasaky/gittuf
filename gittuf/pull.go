package gittuf

import (
	"errors"
	"fmt"
	"strings"

	"github.com/adityasaky/gittuf/internal/gitstore"
	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/sirupsen/logrus"
	tufdata "github.com/theupdateframework/go-tuf/data"
)

func Pull(store *gitstore.GitStore, remoteName string, refName string) error {
	// TODO: If changes are invalid, what state should gitstore be in?
	currentState := store.State()
	repository := store.Repository()

	// First we check for updated states on the remote
	oldStateID := currentState.Tip()
	err := currentState.FetchFromRemote(remoteName)
	if err != nil {
		return err
	}
	newStateID := currentState.Tip()
	if oldStateID == newStateID {
		logrus.Debug("Latest state available already")
	}

	targetName, _ := CreateGitTarget(refName, GitBranchRef)
	lastTrustedStateID, err := store.LastTrusted(targetName)
	if err != nil {
		return err
	}

	lastTrustedState, err := store.SpecificState(lastTrustedStateID)
	if err != nil {
		return err
	}

	currentTargets, _, err := getTargetsRoleForTarget(currentState, targetName)
	if err != nil {
		return err
	}

	remoteHash, err := fetchRef(repository, remoteName, refName)
	if err != nil {
		return err
	}

	if newStateID == lastTrustedStateID {
		logrus.Debug("Latest available state is already last trusted state")
	}

	pathStates, err := getPathToState(store, lastTrustedStateID, newStateID)
	if err != nil {
		return err
	}

	// We need to fetch the requisite trees to ensure validation works
	latestRecordedCommit, err := validateSuccessiveStates(lastTrustedState, pathStates, targetName)
	if err != nil {
		return err
	}

	if remoteHash != convertTUFHashHexBytesToPlumbingHash(currentTargets.Targets[targetName].Hashes["sha1"]) {
		return fmt.Errorf("remote updated without change in state")
	}

	if err = store.UpdateTrustedState(targetName, newStateID); err != nil {
		return err
	}

	// Now we can actually update the ref to point to the commit recorded in new trusted state
	worktree, err := repository.Worktree()
	if err != nil {
		return err
	}

	/*
		TODO: evaluate this Reset invocation. It can be dangerous and an unhandled
		edge case can result in the loss of information.
	*/
	return worktree.Reset(&git.ResetOptions{
		Commit: convertTUFHashHexBytesToPlumbingHash(latestRecordedCommit),
		Mode:   git.MergeReset,
	})
}

func getPathToState(store *gitstore.GitStore, aID, bID string) ([]*gitstore.State, error) {
	// TODO: We should cache this so we have a forward path from aID for future checks
	intermediateStates := []*gitstore.State{}

	bState, err := store.SpecificState(bID)
	if err != nil {
		return []*gitstore.State{}, err
	}

	iter := bState
	for {
		iterTip, err := bState.GetCommitObjectFromHash(iter.TipHash())
		if err != nil {
			return []*gitstore.State{}, err

		}

		if iterTip.ID().String() == aID {
			break
		}

		intermediateStates = append([]*gitstore.State{iter}, intermediateStates...)

		parentState, err := store.SpecificState(string(iterTip.ParentHashes[0].String()))
		if err != nil {
			return []*gitstore.State{}, err
		}
		iter = parentState
	}

	// TODO: loop only when needed
	for _, s := range intermediateStates {
		logrus.Debugf("Discovered intermediate state %s", s.Tip())
	}

	return intermediateStates, nil
}

func fetch(repository *git.Repository, remoteName string) error {
	c, err := repository.Config()
	if err != nil {
		return err
	}
	err = repository.Fetch(&git.FetchOptions{
		RemoteName: remoteName,
		RefSpecs:   c.Remotes[remoteName].Fetch,
	})
	if err != nil && errors.Is(err, git.NoErrAlreadyUpToDate) {
		return nil
	}
	return err
}

func fetchRef(repository *git.Repository, remoteName string, refName string) (plumbing.Hash, error) {
	// We do a regular fetch and then also explicitly fetch the ref we care about
	// in case .git/config has been modified.
	err := fetch(repository, remoteName)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	fetchOptions := &git.FetchOptions{
		RemoteName: remoteName,
		RefSpecs: []gitconfig.RefSpec{
			gitconfig.RefSpec(fmt.Sprintf("refs/heads/%s:refs/remotes/%s/%s", refName, remoteName, refName)),
		},
	}
	err = repository.Fetch(fetchOptions)
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return plumbing.ZeroHash, err
	}

	remoteRef, err := repository.Reference(
		plumbing.ReferenceName(
			fmt.Sprintf("refs/remotes/%s/%s", remoteName, refName),
		),
		true,
	)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	return remoteRef.Hash(), nil
}

func validateSuccessiveStates(sourceState *gitstore.State, pathStates []*gitstore.State, targetName string) (tufdata.HexBytes, error) {
	currentState := sourceState
	currentTargets, _, err := getTargetsRoleForTarget(sourceState, targetName)
	if err != nil {
		return tufdata.HexBytes{}, err
	}

	for i := range pathStates {
		nextState := pathStates[i]
		logrus.Debugf("Comparing states %s -> %s", currentState.Tip(), nextState.Tip())

		currentTree, err := getTreeObjectForTargetState(currentState, currentTargets, targetName)
		if err != nil {
			return tufdata.HexBytes{}, err
		}

		nextTargets, nextRole, err := getTargetsRoleForTarget(nextState, targetName)
		if err != nil {
			return tufdata.HexBytes{}, err
		}
		nextTree, err := getTreeObjectForTargetState(nextState, nextTargets, targetName)
		if err != nil {
			return tufdata.HexBytes{}, err
		}

		logrus.Debugf("Comparing trees %s -> %s", currentTree.Hash.String(), nextTree.Hash.String())

		if nextTree.Hash != currentTree.Hash {
			// This next call is okay because we've verified signatures when loading nextTargets
			signers, err := nextState.GetUnverifiedSignersForRole(nextRole)
			if err != nil {
				return tufdata.HexBytes{}, err
			}

			logrus.Debugf("Target %s in state %s is signed by: %s", targetName, pathStates[i].Tip(), strings.Join(signers, ", "))

			changes, err := currentTree.Diff(nextTree)
			if err != nil {
				return tufdata.HexBytes{}, err
			}

			err = validateChanges(currentState, changes, signers)
			if err != nil {
				return tufdata.HexBytes{}, err
			}
		}

		currentState = pathStates[i]
		currentTargets = nextTargets
	}

	return currentTargets.Targets[targetName].Hashes["sha1"], nil
}
