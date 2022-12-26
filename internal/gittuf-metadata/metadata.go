package metadata

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	tufdata "github.com/theupdateframework/go-tuf/data"
)

const LastTrustedRef = "refs/gittuf/last-trusted"

func InitNamespace(repoRoot string) error {
	// FIXME: this does not handle detached gitdir?
	_, err := os.Stat(filepath.Join(repoRoot, ".git", PolicyStateRef))
	if os.IsNotExist(err) {
		err := os.Mkdir(filepath.Join(repoRoot, ".git", "refs", "gittuf"), 0755)
		if err != nil {
			return err
		}
		err = os.WriteFile(filepath.Join(repoRoot, ".git", PolicyStateRef), plumbing.ZeroHash[:], 0644)
		if err != nil {
			return err
		}
		err = os.WriteFile(filepath.Join(repoRoot, ".git", LastTrustedRef), plumbing.ZeroHash[:], 0644)
		if err != nil {
			return err
		}
	}
	return nil
}

type GitTUFMetadata struct {
	repository  *git.Repository
	policyState *PolicyState
	lastTrusted plumbing.Hash
}

func InitMetadata(repoRoot string, rootPublicKeys []tufdata.PublicKey, metadata map[string][]byte) (*GitTUFMetadata, error) {
	err := InitNamespace(repoRoot)
	if err != nil {
		return &GitTUFMetadata{}, err
	}

	repo, err := git.PlainOpen(repoRoot)
	if err != nil {
		return &GitTUFMetadata{}, err
	}

	state, err := initPolicyState(repo, rootPublicKeys, metadata)
	if err != nil {
		return &GitTUFMetadata{}, err
	}

	return &GitTUFMetadata{
		repository:  repo,
		policyState: state,
		lastTrusted: plumbing.ZeroHash,
	}, nil
}

func LoadGitTUFMetadataHandler(repoRoot string) (*GitTUFMetadata, error) {
	repo, err := git.PlainOpen(repoRoot)
	if err != nil {
		return &GitTUFMetadata{}, err
	}

	stateRef, err := repo.Reference(plumbing.ReferenceName(PolicyStateRef), true)
	if err != nil {
		return &GitTUFMetadata{}, err
	}

	if stateRef.Hash().IsZero() {
		return &GitTUFMetadata{
			repository: repo,
			policyState: &PolicyState{
				metadataStaging:     map[string][]byte{},
				keysStaging:         map[string][]byte{},
				repository:          repo,
				tip:                 plumbing.ZeroHash,
				tree:                plumbing.ZeroHash,
				metadataIdentifiers: map[string]object.TreeEntry{},
				rootKeys:            map[string]object.TreeEntry{},
				written:             true,
			},
			lastTrusted: plumbing.ZeroHash,
		}, nil
	}

	state, err := loadState(repo, stateRef.Hash())
	if err != nil {
		return &GitTUFMetadata{}, err
	}

	lastTrustedRef, err := repo.Reference(plumbing.ReferenceName(LastTrustedRef), true)
	if err != nil {
		return &GitTUFMetadata{}, err
	}

	return &GitTUFMetadata{
		repository:  repo,
		policyState: state,
		lastTrusted: lastTrustedRef.Hash(),
	}, nil
}

func (g *GitTUFMetadata) GetLastTrusted() (map[string]string, error) {
	if g.lastTrusted.IsZero() {
		return map[string]string{}, nil
	}

	_, contents, err := readBlob(g.repository, g.lastTrusted)
	if err != nil {
		return map[string]string{}, err
	}
	var lastTrusted map[string]string
	err = json.Unmarshal(contents, &lastTrusted)
	return lastTrusted, err
}

func (g *GitTUFMetadata) WriteLastTrusted(lastTrusted map[string]string) error {
	contents, err := json.Marshal(lastTrusted)
	if err != nil {
		return err
	}
	contentID, err := writeBlob(g.repository, contents)
	if err != nil {
		return err
	}

	g.lastTrusted = contentID
	oldRef, err := g.repository.Reference(plumbing.ReferenceName(LastTrustedRef), true)
	if err != nil {
		return err
	}
	newRef := plumbing.NewHashReference(plumbing.ReferenceName(LastTrustedRef), contentID)

	return g.repository.Storer.CheckAndSetReference(newRef, oldRef)
}

// State returns the current state.
func (g *GitTUFMetadata) State() *PolicyState {
	return g.policyState
}

func (g *GitTUFMetadata) Repository() *git.Repository {
	return g.repository
}

// SpecificState returns the specified state.
func (g *GitTUFMetadata) SpecificState(stateID string) (*PolicyState, error) {
	stateHash := plumbing.NewHash(stateID)
	return loadState(g.repository, stateHash)
}

func (g *GitTUFMetadata) LastTrusted(target string) (string, error) {
	lastTrusted, err := g.GetLastTrusted()
	if err != nil {
		return "", err
	}
	stateID, exists := lastTrusted[target]
	if !exists {
		return "", fmt.Errorf("no trusted state found for %s", target)
	}
	return stateID, nil
}

func (g *GitTUFMetadata) UpdateTrustedState(target, stateID string) error {
	lastTrusted, err := g.GetLastTrusted()
	if err != nil {
		return err
	}
	lastTrusted[target] = stateID

	return g.WriteLastTrusted(lastTrusted)
}

func (g *GitTUFMetadata) ReferenceState(refName string) (*ReferenceState, error) {
	trustedKeys := []tufdata.PublicKey{}
	// FIXME: how do we associate reference states at the corresponding policy states? Is it safe to infer trustedKeys?
	return LoadReferenceStateForRef(g.repository, refName, trustedKeys)
}
