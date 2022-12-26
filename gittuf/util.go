package gittuf

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"

	metadata "github.com/adityasaky/gittuf/internal/gittuf-metadata"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"

	tufdata "github.com/theupdateframework/go-tuf/data"
	tufkeys "github.com/theupdateframework/go-tuf/pkg/keys"
	tufsign "github.com/theupdateframework/go-tuf/sign"
	tufverify "github.com/theupdateframework/go-tuf/verify"
)

var METADATADIR = "../metadata" // FIXME: embed metadata in Git repo

func loadRoot(state *metadata.PolicyState) (*tufdata.Root, error) {
	var role tufdata.Root

	roleBytes, err := state.GetCurrentMetadataBytes("root")
	if err != nil {
		return &tufdata.Root{}, err
	}

	var roleMb tufdata.Signed
	err = json.Unmarshal(roleBytes, &roleMb)
	if err != nil {
		return &tufdata.Root{}, err
	}

	err = json.Unmarshal(roleMb.Signed, &role)
	if err != nil {
		return &tufdata.Root{}, err
	}

	rootKeys, err := state.GetAllRootKeys()
	if err != nil {
		return &tufdata.Root{}, err
	}

	msg, err := cjson.EncodeCanonical(role)
	if err != nil {
		return &tufdata.Root{}, err
	}

	verifiedKeyIDs := []string{}
	for _, sig := range roleMb.Signatures {
		key := rootKeys[sig.KeyID]
		verifier, err := tufkeys.GetVerifier(&key)
		if err != nil {
			return &tufdata.Root{}, err
		}
		err = verifier.Verify(msg, sig.Signature)
		if err != nil {
			// TODO: do we fail for any sig that fails? What's the threshold
			// strategy?
			return &tufdata.Root{}, err
		}
		verifiedKeyIDs = append(verifiedKeyIDs, sig.KeyID)
	}

	if len(verifiedKeyIDs) == 0 {
		return &tufdata.Root{}, fmt.Errorf("root role verified with zero keys")
	}

	return &role, err
}

func loadTargets(state *metadata.PolicyState, roleName string, db *tufverify.DB) (*tufdata.Targets, error) {
	var role tufdata.Targets

	roleBytes, err := state.GetCurrentMetadataBytes(roleName)
	if err != nil {
		return &role, err
	}

	var roleMb tufdata.Signed
	err = json.Unmarshal(roleBytes, &roleMb)
	if err != nil {
		return &role, err
	}

	err = db.VerifySignatures(&roleMb, roleName)
	if err != nil {
		return &role, fmt.Errorf("%w of role %s", err, roleName)
	}

	err = json.Unmarshal(roleMb.Signed, &role)
	return &role, err
}

func getTreeObjectForTargetState(state *metadata.PolicyState, targets *tufdata.Targets, targetName string) (*object.Tree, error) {
	lastTrustedCommit, err := state.GetCommitObjectFromHash(
		convertTUFHashHexBytesToPlumbingHash(
			targets.Targets[targetName].Hashes["sha1"],
		),
	)
	if err != nil {
		return &object.Tree{}, err
	}
	return state.GetTreeObjectFromHash(lastTrustedCommit.TreeHash)
}

func LoadEd25519PublicKeyFromSslib(path string) (tufdata.PublicKey, error) {
	var pubKey tufdata.PublicKey
	pubKeyData, err := os.ReadFile(path)
	if err != nil {
		return tufdata.PublicKey{}, err
	}
	err = json.Unmarshal(pubKeyData, &pubKey)
	if err != nil {
		return tufdata.PublicKey{}, err
	}

	return pubKey, nil
}

func LoadEd25519PrivateKeyFromSslib(path string) (tufdata.PrivateKey, error) {
	var privKey tufdata.PrivateKey
	privKeyData, err := os.ReadFile(path)
	if err != nil {
		return tufdata.PrivateKey{}, err
	}
	err = json.Unmarshal(privKeyData, &privKey)
	if err != nil {
		return tufdata.PrivateKey{}, err
	}

	var keyValue KeyValue
	err = json.Unmarshal(privKey.Value, &keyValue)
	if err != nil {
		return tufdata.PrivateKey{}, err
	}
	/*
		Here, the assumption is that the key pair is in the securesystemslib
		format. However, the default python-sslib format does not contain the
		private and the public halves of the key in the "private" field as
		go-tuf expects. So, while a keypair can be generated using python-sslib,
		the public portion must be appended to the private portion in the JSON
		representation.
	*/
	if len(keyValue.Private) < ed25519.PrivateKeySize {
		fullPrivateValue, err := json.Marshal(KeyValue{
			Private: append(keyValue.Private, keyValue.Public...),
			Public:  keyValue.Public,
		})
		if err != nil {
			return tufdata.PrivateKey{}, err
		}
		return tufdata.PrivateKey{
			Type:       privKey.Type,
			Scheme:     privKey.Scheme,
			Algorithms: privKey.Algorithms,
			Value:      fullPrivateValue,
		}, nil
	}

	return privKey, nil
}

func GetEd25519PublicKeyFromPrivateKey(privKey *tufdata.PrivateKey) (tufdata.PublicKey, error) {
	var keyValue KeyValue

	err := json.Unmarshal(privKey.Value, &keyValue)
	if err != nil {
		return tufdata.PublicKey{}, err
	}

	newValue, err := json.Marshal(KeyValue{
		Private: []byte{},
		Public:  keyValue.Public,
	})
	if err != nil {
		return tufdata.PublicKey{}, err
	}

	return tufdata.PublicKey{
		Type:       privKey.Type,
		Scheme:     privKey.Scheme,
		Algorithms: privKey.Algorithms,
		Value:      newValue,
	}, nil

}

type KeyValue struct {
	Private []byte `json:"private,omitempty"`
	Public  []byte `json:"public,omitempty"`
}

func generateAndSignMbFromStruct(content interface{}, keys []tufdata.PrivateKey) (tufdata.Signed, error) {
	var newMb tufdata.Signed
	newJson, err := json.Marshal(content)
	if err != nil {
		return newMb, err
	}
	newMb = tufdata.Signed{
		Signed:     newJson,
		Signatures: []tufdata.Signature{},
	}
	for _, key := range keys {
		signer, err := tufkeys.GetSigner(&key)
		if err != nil {
			return newMb, err
		}
		err = tufsign.Sign(&newMb, signer)
		if err != nil {
			return newMb, err
		}
	}
	return newMb, nil
}
