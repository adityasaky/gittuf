package metadata

import (
	"encoding/json"
	"fmt"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	tufdata "github.com/theupdateframework/go-tuf/data"
	tufkeys "github.com/theupdateframework/go-tuf/pkg/keys"
)

const ReferenceStateRef = "refs/gittuf/reference-state"

type ReferenceState struct {
	LastEntry plumbing.Hash
	Tip       plumbing.Hash
}

func LoadReferenceStateForRef(repository *git.Repository, refName string, trustedKeys []tufdata.PublicKey) (*ReferenceState, error) {
	ns := fmt.Sprintf("%s/%s", ReferenceStateRef, refName)

	ref, err := repository.Reference(plumbing.ReferenceName(ns), true)
	if err != nil {
		return &ReferenceState{}, err
	}

	if ref.Hash().IsZero() {
		return &ReferenceState{
			LastEntry: plumbing.ZeroHash,
			Tip:       plumbing.ZeroHash,
		}, nil
	}

	_, contents, err := readBlob(repository, ref.Hash())
	if err != nil {
		return &ReferenceState{}, err
	}

	var e tufdata.Signed
	err = json.Unmarshal(contents, &e)
	if err != nil {
		return &ReferenceState{}, err
	}

	var r ReferenceState
	err = json.Unmarshal(e.Signed, &r)
	if err != nil {
		return &ReferenceState{}, err
	}

	msg, err := cjson.EncodeCanonical(r)
	if err != nil {
		return &ReferenceState{}, err
	}

	for _, k := range trustedKeys {
		verifier, err := tufkeys.GetVerifier(&k)
		if err != nil {
			return &ReferenceState{}, err
		}

		// We always expect a single signature
		if err = verifier.Verify(msg, e.Signatures[0].Signature); err != nil {
			// Try next key
			continue
		}

		// We get here only if a signature verification is successful
		return &r, nil
	}

	return &ReferenceState{}, fmt.Errorf("no entry found with signature from trusted key")
}
