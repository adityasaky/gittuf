package gittuf

import (
	"encoding/json"
	"fmt"
	"reflect"

	metadata "github.com/adityasaky/gittuf/internal/gittuf-metadata"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	tufdata "github.com/theupdateframework/go-tuf/data"
	tuftargets "github.com/theupdateframework/go-tuf/pkg/targets"
	tufverify "github.com/theupdateframework/go-tuf/verify"
)

const AllowRule = "allow-*"

/*
VerifyTrustedStates compares two TUF states of the repository, stateA and
stateB, and validates if the repository can move from stateA to stateB.
Both states are specified as tips of the gittuf namespace. Note that this API
does NOT update the contents of the gittuf namespace.
*/
func VerifyTrustedStates(target string, stateA string, stateB string) error {
	if stateA == stateB {
		return nil
	}

	// Verify the ref is in valid git format
	if !IsValidGitTarget(target) {
		return fmt.Errorf("specified ref '%s' is not in valid git format", target)
	}

	repoRoot, err := GetRepoRootDir()
	if err != nil {
		return err
	}

	stateARepo, err := metadata.LoadAtState(repoRoot, stateA)
	if err != nil {
		return err
	}

	// FIXME: what if target / rule didn't exist before and no metadata exists?
	stateARefTree, err := getStateTree(stateARepo, target)
	if err != nil {
		return err
	}

	stateBRepo, err := metadata.LoadAtState(repoRoot, stateB)
	if err != nil {
		return err
	}
	stateBRefTree, err := getStateTree(stateBRepo, target)
	if err != nil {
		return err
	}

	// Get keys used signing role of target in stateB
	_, roleName, err := getTargetsRoleForTarget(stateBRepo, target)
	if err != nil {
		return err
	}
	roleBytes, err := stateBRepo.GetCurrentMetadataBytes(roleName)
	if err != nil {
		return err
	}
	var roleSigned tufdata.Signed
	err = json.Unmarshal(roleBytes, &roleSigned)
	if err != nil {
		return err
	}
	usedKeyIDs := []string{}
	for _, sig := range roleSigned.Signatures {
		usedKeyIDs = append(usedKeyIDs, sig.KeyID)
	}

	changes, err := stateARefTree.Diff(stateBRefTree)
	if err != nil {
		return err
	}

	return validateChanges(stateARepo, changes, usedKeyIDs)
}

/*
VerifyState checks that a target has the hash specified in the TUF delegations tree.
*/
func VerifyState(store *metadata.GitTUFMetadata, target string) error {
	state := store.State()
	activeID, err := getCurrentCommitID(target)
	if err != nil {
		return err
	}

	currentTargets, role, err := getTargetsRoleForTarget(state, target)
	if err != nil {
		return err
	}

	currentTargetsID := currentTargets.Targets[target].Hashes["sha1"]
	if !reflect.DeepEqual(currentTargetsID, activeID) {
		return fmt.Errorf("role %s has recorded different hash value %s from current hash %s", role, currentTargetsID.String(), activeID.String())
	}

	lastTrustedStateID, err := store.LastTrusted(target)
	if err != nil {
		return err
	}
	lastTrustedState, err := store.SpecificState(lastTrustedStateID)
	if err != nil {
		return err
	}
	lastTrustedTargets, role, err := getTargetsRoleForTarget(lastTrustedState, target)
	if err != nil {
		return err
	}
	lastTrustedTargetsID := lastTrustedTargets.Targets[target].Hashes["sha1"]
	if !reflect.DeepEqual(lastTrustedTargetsID, activeID) {
		return fmt.Errorf("role %s has recorded different hash value %s from current hash %s", role, lastTrustedTargetsID.String(), activeID.String())
	}

	return nil
}

func InitializeTopLevelDB(state *metadata.PolicyState) (*tufverify.DB, error) {
	db := tufverify.NewDB()

	rootRole, err := loadRoot(state)
	if err != nil {
		return db, err
	}

	for id, key := range rootRole.Keys {
		if err := db.AddKey(id, key); err != nil {
			return db, err
		}
	}

	for name, role := range rootRole.Roles {
		if err := db.AddRole(name, role); err != nil {
			return db, err
		}
	}

	return db, nil
}

func InitializeDBUntilRole(state *metadata.PolicyState, roleName string) (*tufverify.DB, error) {
	db, err := InitializeTopLevelDB(state)
	if err != nil {
		return db, err
	}

	if roleName == "targets" {
		// The top level DB has that covered
		return db, nil
	}

	toBeChecked := []string{"targets"}

	for {
		if len(toBeChecked) == 0 {
			if len(roleName) != 0 {
				return db, fmt.Errorf("role %s not found", roleName)
			} else {
				// We found every reachable role
				return db, nil
			}
		}

		current := toBeChecked[0]
		toBeChecked = toBeChecked[1:]

		targets, err := loadTargets(state, current, db)
		if err != nil {
			return db, err
		}

		if targets.Delegations == nil {
			continue
		}

		for id, key := range targets.Delegations.Keys {
			db.AddKey(id, key)
		}

		for _, d := range targets.Delegations.Roles {
			db.AddRole(d.Name, &tufdata.Role{
				KeyIDs:    d.KeyIDs,
				Threshold: d.Threshold,
			})
			if d.Name == roleName {
				return db, nil
			}
			toBeChecked = append(toBeChecked, d.Name)
		}
	}
}

func getCurrentCommitID(target string) (tufdata.HexBytes, error) {
	// We check if target has the form git:...
	// In future, if multiple schemes are supported, this function can dispatch
	// to different parsers.

	if !IsValidGitTarget(target) {
		return tufdata.HexBytes{}, fmt.Errorf("%s is not a Git object", target)
	}

	refName, refType, err := ParseGitTarget(target)
	if err != nil {
		return tufdata.HexBytes{}, err
	}

	return GetTipCommitIDForRef(refName, refType)
}

func getTargetsRoleForTarget(state *metadata.PolicyState, target string) (*tufdata.Targets, string, error) {
	db, err := InitializeTopLevelDB(state)
	if err != nil {
		return &tufdata.Targets{}, "", err
	}

	topLevelTargets, err := loadTargets(state, "targets", db)
	if err != nil {
		return &tufdata.Targets{}, "", err
	}

	if _, ok := topLevelTargets.Targets[target]; ok {
		return topLevelTargets, "targets", nil
	}

	iterator, err := tuftargets.NewDelegationsIterator(target, db)
	if err != nil {
		return &tufdata.Targets{}, "", err
	}

	for {
		d, ok := iterator.Next()
		if !ok {
			return &tufdata.Targets{}, "",
				fmt.Errorf("delegation not found for target %s", target)
		}

		delegatedRole, err := loadTargets(state, d.Delegatee.Name, d.DB)
		if err != nil {
			return &tufdata.Targets{}, "", err
		}

		if _, ok := delegatedRole.Targets[target]; ok {
			return delegatedRole, d.Delegatee.Name, nil
		}

		if delegatedRole.Delegations != nil {
			newDB, err := tufverify.NewDBFromDelegations(delegatedRole.Delegations)
			if err != nil {
				return &tufdata.Targets{}, "", err
			}
			err = iterator.Add(delegatedRole.Delegations.Roles, d.Delegatee.Name, newDB)
			if err != nil {
				return &tufdata.Targets{}, "", err
			}
		}
	}
}

func getStateTree(metadataRepo *metadata.PolicyState, target string) (*object.Tree, error) {
	mainRepo, err := GetRepoHandler()
	if err != nil {
		return &object.Tree{}, err
	}

	stateTargets, _, err := getTargetsRoleForTarget(metadataRepo, target)
	if err != nil {
		return &object.Tree{}, err
	}

	// This is NOT in the gittuf namespace
	stateEntryHash := plumbing.NewHash(stateTargets.Targets[target].Hashes["sha1"].String())
	stateRefCommit, err := mainRepo.CommitObject(stateEntryHash)
	if err != nil {
		return &object.Tree{}, err
	}
	return mainRepo.TreeObject(stateRefCommit.TreeHash)
}

func getDelegationForTarget(state *metadata.PolicyState, target string) (tufdata.DelegatedRole, error) {
	db, err := InitializeTopLevelDB(state)
	if err != nil {
		return tufdata.DelegatedRole{}, err
	}

	iterator, err := tuftargets.NewDelegationsIterator(target, db)
	if err != nil {
		return tufdata.DelegatedRole{}, err
	}

	for {
		d, ok := iterator.Next()
		if !ok {
			return tufdata.DelegatedRole{},
				fmt.Errorf("delegation not found for target %s", target)
		}

		match, err := d.Delegatee.MatchesPath(target)
		if err != nil {
			return tufdata.DelegatedRole{}, err
		}
		if match {
			return d.Delegatee, nil
		}

		delegatedRole, err := loadTargets(state, d.Delegatee.Name, d.DB)
		if err != nil {
			return tufdata.DelegatedRole{}, err
		}

		if delegatedRole.Delegations != nil {
			newDB, err := tufverify.NewDBFromDelegations(delegatedRole.Delegations)
			if err != nil {
				return tufdata.DelegatedRole{}, err
			}
			err = iterator.Add(delegatedRole.Delegations.Roles, d.Delegatee.Name, newDB)
			if err != nil {
				return tufdata.DelegatedRole{}, err
			}
		}
	}
}

func validateUsedKeyIDs(authorizedKeyIDs []string, usedKeyIDs []string) bool {
	set := map[string]bool{}
	for _, k := range authorizedKeyIDs {
		set[k] = true
	}
	for _, k := range usedKeyIDs {
		if _, ok := set[k]; !ok {
			return false
		}
	}
	return true
}

func validateRule(ruleState *metadata.PolicyState, path string, usedKeyIDs []string) error {
	ruleInA, err := getDelegationForTarget(ruleState, path)
	if err != nil {
		return err
	}
	if ruleInA.Name == AllowRule {
		return nil
	}

	// TODO: threshold
	if !validateUsedKeyIDs(ruleInA.KeyIDs, usedKeyIDs) {
		return fmt.Errorf("unauthorized change to file %s", path)
	}

	return nil
}

func validateChanges(ruleState *metadata.PolicyState, changes object.Changes, usedKeyIDs []string) error {
	for _, c := range changes {
		// For each change to a file, we want to verify that the policy allows
		// the keys that were used to sign changes for the file.

		// First, we get the delegations entry for the target. If we end up at
		// the catch all rule, we move on to the next change.

		// Once we have a delegations entry, we get a list of keys authorized
		// to sign for the target. We then check if the keys used were part of
		// this authorized set.

		// If the change includes a rename, we follow the above rules for the
		// original name AND the new name. This ensures that a rename does not
		// result in a file being written to a protected namespace.

		if len(c.From.Name) > 0 {
			if err := validateRule(ruleState, c.From.Name, usedKeyIDs); err != nil {
				return err
			}
		}

		if c.From.Name != c.To.Name && len(c.To.Name) > 0 {
			if err := validateRule(ruleState, c.To.Name, usedKeyIDs); err != nil {
				return err
			}
		}

	}
	return nil
}
