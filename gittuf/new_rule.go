package gittuf

import (
	"encoding/json"
	"fmt"

	metadata "github.com/adityasaky/gittuf/internal/gittuf-metadata"
	tufdata "github.com/theupdateframework/go-tuf/data"
	tufkeys "github.com/theupdateframework/go-tuf/pkg/keys"
	tufsign "github.com/theupdateframework/go-tuf/sign"
)

func NewRule(
	state *metadata.PolicyState,
	role string,
	roleKeys []tufdata.PrivateKey,
	ruleName string,
	ruleThreshold int,
	ruleTerminating bool,
	protectPaths []string,
	allowedKeys []tufdata.PublicKey) (tufdata.Signed, error) {

	if state.HasFile(ruleName) {
		return tufdata.Signed{}, fmt.Errorf("metadata for rule %s already exists", ruleName)
	}

	db, err := InitializeDBUntilRole(state, role)
	if err != nil {
		return tufdata.Signed{}, err
	}
	roleTargets, err := loadTargets(state, role, db)
	if err != nil {
		return tufdata.Signed{}, err
	}

	allowedKeyIds := []string{}
	allowedKeysMap := map[string]*tufdata.PublicKey{}
	for _, k := range allowedKeys {
		keyIds := k.IDs()
		allowedKeyIds = append(allowedKeyIds, keyIds...)
		for _, keyId := range keyIds {
			allowedKeysMap[keyId] = &tufdata.PublicKey{
				Type:       k.Type,
				Scheme:     k.Scheme,
				Algorithms: k.Algorithms,
				Value:      k.Value,
			}
		}
	}

	if roleTargets.Delegations == nil {
		roleTargets.Delegations = &tufdata.Delegations{
			Keys:  map[string]*tufdata.PublicKey{},
			Roles: []tufdata.DelegatedRole{createAllowRule()}, // TODO: Is this okay?
		}
	}
	roleDelegations := *roleTargets.Delegations

	for id, key := range allowedKeysMap {
		// TODO: should we check for key ID collisions here? If not, the below
		// snippet can be modified to merely write the new key without checking
		// for an existing entry. #prematureOptimization?
		if _, ok := roleDelegations.Keys[id]; !ok {
			roleDelegations.Keys[id] = &tufdata.PublicKey{
				Type:       key.Type,
				Scheme:     key.Scheme,
				Algorithms: key.Algorithms,
				Value:      key.Value,
			}
		}
	}

	for _, existingDelegatedRole := range roleDelegations.Roles {
		if existingDelegatedRole.Name == ruleName {
			return tufdata.Signed{}, fmt.Errorf("rule with name %s already exists", ruleName)
		}
	}

	newRuleDelegation := tufdata.DelegatedRole{
		Name:             ruleName,
		KeyIDs:           allowedKeyIds,
		Threshold:        ruleThreshold,
		Terminating:      ruleTerminating,
		PathHashPrefixes: []string{},
		Paths:            protectPaths,
	}

	roleDelegations.Roles = append(roleDelegations.Roles[:len(roleDelegations.Roles)-1], newRuleDelegation, createAllowRule())
	roleTargets.Delegations = &roleDelegations

	roleTargets.Version += 1

	newRoleJson, err := json.Marshal(roleTargets)
	if err != nil {
		return tufdata.Signed{}, err
	}

	newRoleMb := tufdata.Signed{
		Signed:     newRoleJson,
		Signatures: []tufdata.Signature{},
	}

	for _, key := range roleKeys {
		signer, err := tufkeys.GetSigner(&key)
		if err != nil {
			return tufdata.Signed{}, err
		}
		err = tufsign.Sign(&newRoleMb, signer)
		if err != nil {
			return tufdata.Signed{}, err
		}
	}

	return newRoleMb, nil
}

func createAllowRule() tufdata.DelegatedRole {
	return tufdata.DelegatedRole{
		Name:        AllowRule,
		KeyIDs:      []string{"*"},
		Threshold:   1,
		Terminating: true,
		Paths:       []string{"*"},
	}
}
