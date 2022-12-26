package metadata

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	tufdata "github.com/theupdateframework/go-tuf/data"
)

const (
	PolicyStateRef = "refs/gittuf/policy-state"
	DefaultRemote  = "origin"
	MetadataDir    = "metadata"
	KeysDir        = "keys"
)

func LoadState(repoRoot string) (*PolicyState, error) {
	repo, err := git.PlainOpen(repoRoot)
	if err != nil {
		return &PolicyState{}, err
	}
	ref, err := repo.Reference(plumbing.ReferenceName(PolicyStateRef), true)
	if err != nil {
		return &PolicyState{}, err
	}

	if ref.Hash() == plumbing.ZeroHash {
		return &PolicyState{
			metadataStaging:     map[string][]byte{},
			keysStaging:         map[string][]byte{},
			repository:          repo,
			tip:                 plumbing.ZeroHash,
			tree:                plumbing.ZeroHash,
			metadataIdentifiers: map[string]object.TreeEntry{},
			rootKeys:            map[string]object.TreeEntry{},
			written:             true,
		}, nil
	}

	return loadState(repo, ref.Hash())
}

func LoadAtState(repoRoot string, stateID string) (*PolicyState, error) {
	repo, err := git.PlainOpen(repoRoot)
	if err != nil {
		return &PolicyState{}, nil
	}
	ref, err := repo.Reference(plumbing.ReferenceName(PolicyStateRef), true)
	if err != nil {
		return &PolicyState{}, err
	}

	currentHash := ref.Hash()
	stateHash := plumbing.NewHash(stateID)

	if stateHash == plumbing.ZeroHash || currentHash == plumbing.ZeroHash {
		return &PolicyState{}, fmt.Errorf("can't load gittuf repository at state zero")
	}
	if currentHash == stateHash {
		return LoadState(repoRoot)
	}

	// Check if stateHash is present when tracing back from currentHash
	iteratorHash := currentHash
	for {
		if iteratorHash == stateHash {
			break
		}

		commitObj, err := repo.CommitObject(iteratorHash)
		if err != nil {
			return &PolicyState{}, err
		}

		if len(commitObj.ParentHashes) == 0 {
			return &PolicyState{}, fmt.Errorf("state %s not found in gittuf namespace", stateID)
		}
		if len(commitObj.ParentHashes) > 1 {
			return &PolicyState{}, fmt.Errorf("state %s has multiple parents", iteratorHash.String())
		}

		iteratorHash = commitObj.ParentHashes[0]
	}

	// Now that we've validated it's a valid commit, we can load at that state.
	return loadState(repo, stateHash)
}

type PolicyState struct {
	repository          *git.Repository
	metadataStaging     map[string][]byte // rolename: contents, rolename should NOT include extension
	keysStaging         map[string][]byte // keyID: PubKey
	tip                 plumbing.Hash
	tree                plumbing.Hash
	rootKeys            map[string]object.TreeEntry // keyID: TreeEntry object
	metadataIdentifiers map[string]object.TreeEntry // filename: TreeEntry object
	written             bool
}

func (s *PolicyState) FetchFromRemote(remoteName string) error {
	refSpec := config.RefSpec(fmt.Sprintf("%s:%s", PolicyStateRef, PolicyStateRef))
	options := &git.FetchOptions{
		RemoteName: remoteName,
		RefSpecs:   []config.RefSpec{refSpec},
	}
	err := s.repository.Fetch(options)
	if err != nil {
		if errors.Is(err, git.NoErrAlreadyUpToDate) {
			return nil
		}
		return err
	}

	ref, err := s.repository.Reference(plumbing.ReferenceName(PolicyStateRef), true)
	if err != nil {
		return err
	}
	tipCommit, err := s.repository.CommitObject(ref.Hash())
	if err != nil {
		return err
	}

	s.tip = tipCommit.Hash
	s.tree = tipCommit.TreeHash

	rootKeys := map[string]object.TreeEntry{}
	keysTree, err := s.GetTreeForNamespace(KeysDir)
	if err != nil {
		return err
	}
	for _, e := range keysTree.Entries {
		rootKeys[getNameWithoutExtension(e.Name)] = e
	}
	s.rootKeys = rootKeys

	metadataIdentifiers := map[string]object.TreeEntry{}
	metadataTree, err := s.GetTreeForNamespace(MetadataDir)
	if err != nil {
		return err
	}
	for _, e := range metadataTree.Entries {
		metadataIdentifiers[getNameWithoutExtension(e.Name)] = e
	}
	s.metadataIdentifiers = metadataIdentifiers

	return nil
}

func (s *PolicyState) Tip() string {
	return s.tip.String()
}

func (s *PolicyState) TipHash() plumbing.Hash {
	return s.tip
}

func (s *PolicyState) Tree() (*object.Tree, error) {
	return s.repository.TreeObject(s.tree)
}

func (s *PolicyState) Written() bool {
	return s.written
}

func (s *PolicyState) GetCommitObject(id string) (*object.Commit, error) {
	return s.GetCommitObjectFromHash(plumbing.NewHash(id))
}

func (s *PolicyState) GetCommitObjectFromHash(hash plumbing.Hash) (*object.Commit, error) {
	return s.repository.CommitObject(hash)
}

func (s *PolicyState) GetTreeObject(id string) (*object.Tree, error) {
	return s.GetTreeObjectFromHash(plumbing.NewHash(id))
}

func (s *PolicyState) GetTreeObjectFromHash(hash plumbing.Hash) (*object.Tree, error) {
	return s.repository.TreeObject(hash)
}

func (s *PolicyState) GetTreeForNamespace(namespace string) (*object.Tree, error) {
	tree, err := s.repository.TreeObject(s.tree)
	if err != nil {
		return &object.Tree{}, err
	}
	for _, entry := range tree.Entries {
		if entry.Name == namespace {
			return s.GetTreeObjectFromHash(entry.Hash)
		}
	}
	return &object.Tree{}, fmt.Errorf("tree not found for namespace %s", namespace)
}

func (s *PolicyState) GetMetadataForState(stateID string) (map[string][]byte, error) {
	metadata := map[string][]byte{}

	commit, err := s.GetCommitObject(stateID)
	if err != nil {
		return metadata, err
	}
	tree, err := s.GetTreeObjectFromHash(commit.TreeHash)
	if err != nil {
		return metadata, err
	}

	for _, e := range tree.Entries {
		_, contents, err := readBlob(s.repository, e.Hash)
		if err != nil {
			return map[string][]byte{}, err
		}
		metadata[e.Name] = contents
	}

	return metadata, nil
}

func (s *PolicyState) HasFile(roleName string) bool {
	_, exists := s.metadataIdentifiers[roleName]
	return exists
}

func (s *PolicyState) GetCurrentMetadataBytes(roleName string) ([]byte, error) {
	_, contents, err := readBlob(s.repository, s.metadataIdentifiers[roleName].Hash)
	if err != nil {
		return []byte{}, err
	}
	return contents, nil
}

func (s *PolicyState) GetUnverifiedSignersForRole(roleName string) ([]string, error) {
	contents, err := s.GetCurrentMetadataBytes(roleName)
	if err != nil {
		return []string{}, err
	}

	var mb tufdata.Signed
	err = json.Unmarshal(contents, &mb)
	if err != nil {
		return []string{}, err
	}

	keyIDs := []string{}
	for _, s := range mb.Signatures {
		keyIDs = append(keyIDs, s.KeyID)
	}

	return keyIDs, nil
}

func (s *PolicyState) GetCurrentMetadataString(roleName string) (string, error) {
	contents, err := s.GetCurrentMetadataBytes(roleName)
	return string(contents), err
}

func (s *PolicyState) GetAllCurrentMetadata() (map[string][]byte, error) {
	metadata := map[string][]byte{}
	for roleName, treeEntry := range s.metadataIdentifiers {
		_, contents, err := readBlob(s.repository, treeEntry.Hash)
		if err != nil {
			return map[string][]byte{}, err
		}
		metadata[roleName] = contents
	}
	return metadata, nil
}

func (s *PolicyState) GetRootKey(keyID string) (tufdata.PublicKey, error) {
	var key tufdata.PublicKey
	contents, err := s.GetRootKeyBytes(keyID)
	if err != nil {
		return tufdata.PublicKey{}, err
	}
	err = json.Unmarshal(contents, &key)
	return key, err
}

func (s *PolicyState) GetRootKeyBytes(keyID string) ([]byte, error) {
	_, contents, err := readBlob(s.repository, s.rootKeys[keyID].Hash)
	return contents, err
}

func (s *PolicyState) GetRootKeyString(keyID string) (string, error) {
	contents, err := s.GetRootKeyBytes(keyID)
	return string(contents), err
}

func (s *PolicyState) GetAllRootKeys() (map[string]tufdata.PublicKey, error) {
	keys := map[string]tufdata.PublicKey{}
	for keyID, treeEntry := range s.rootKeys {
		_, contents, err := readBlob(s.repository, treeEntry.Hash)
		if err != nil {
			return map[string]tufdata.PublicKey{}, err
		}

		var key tufdata.PublicKey
		err = json.Unmarshal(contents, &key)
		if err != nil {
			return map[string]tufdata.PublicKey{}, err
		}

		keys[keyID] = key
	}
	return keys, nil
}

func (s *PolicyState) StageMetadata(roleName string, contents []byte) {
	s.metadataStaging[roleName] = contents
	s.written = false
}

func (s *PolicyState) StageMetadataAndCommit(roleName string, contents []byte) error {
	s.StageMetadata(roleName, contents)
	return s.Commit()
}

func (s *PolicyState) StageMultipleMetadata(metadata map[string][]byte) {
	for roleName, contents := range metadata {
		s.StageMetadata(roleName, contents)
	}
}

func (s *PolicyState) StageAndCommitMultipleMetadata(metadata map[string][]byte) error {
	s.StageMultipleMetadata(metadata)
	return s.Commit()
}

func (s *PolicyState) StageKey(key tufdata.PublicKey) error {
	s.written = false
	contents, err := json.Marshal(key)
	if err != nil {
		return err
	}
	keyIDs := key.IDs()
	for _, keyID := range keyIDs {
		s.keysStaging[keyID] = contents
	}
	return nil
}

func (s *PolicyState) StageKeyAndCommit(key tufdata.PublicKey) error {
	err := s.StageKey(key)
	if err != nil {
		return err
	}
	return s.Commit()
}

func (s *PolicyState) StageKeys(keys []tufdata.PublicKey) error {
	for _, key := range keys {
		err := s.StageKey(key)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *PolicyState) StageKeysAndCommit(keys []tufdata.PublicKey) error {
	err := s.StageKeys(keys)
	if err != nil {
		return err
	}
	return s.Commit()
}

func (s *PolicyState) Commit() error {
	if s.Written() {
		// Nothing to do
		return nil
	}

	// We need to create a new tree that includes unchanged entries and the
	// newly staged metadata.
	metadataEntries := []object.TreeEntry{}
	for roleName, treeEntry := range s.metadataIdentifiers {
		if _, exists := s.metadataStaging[roleName]; exists {
			// We'll not reuse the entries for staged metadata
			continue
		}
		metadataEntries = append(metadataEntries, treeEntry)
	}

	// Write staged blobs and add them to currentEntries
	for roleName, contents := range s.metadataStaging {
		identifier, err := writeBlob(s.repository, contents)
		if err != nil {
			return err
		}
		treeEntry := object.TreeEntry{
			Name: fmt.Sprintf("%s.json", roleName),
			Mode: filemode.Regular,
			Hash: identifier,
		}
		s.metadataIdentifiers[roleName] = treeEntry
		metadataEntries = append(metadataEntries, treeEntry)
	}

	// Create a new tree object
	metadataTreeHash, err := writeTree(s.repository, metadataEntries)
	if err != nil {
		return err
	}

	// FIXME: DRY?
	rootKeyEntries := []object.TreeEntry{}
	for keyID, treeEntry := range s.rootKeys {
		if _, exists := s.keysStaging[keyID]; exists {
			continue
		}
		rootKeyEntries = append(rootKeyEntries, treeEntry)
	}

	for keyID, contents := range s.keysStaging {
		identifier, err := writeBlob(s.repository, contents)
		if err != nil {
			return err
		}
		treeEntry := object.TreeEntry{
			Name: fmt.Sprintf("%s.pub", keyID),
			Mode: filemode.Regular,
			Hash: identifier,
		}
		s.rootKeys[keyID] = treeEntry
		rootKeyEntries = append(rootKeyEntries, treeEntry)
	}

	keysTreeHash, err := writeTree(s.repository, rootKeyEntries)
	if err != nil {
		return err
	}

	topLevelEntries := []object.TreeEntry{}
	topLevelEntries = append(topLevelEntries, object.TreeEntry{
		Name: MetadataDir,
		Mode: filemode.Dir,
		Hash: metadataTreeHash,
	})
	topLevelEntries = append(topLevelEntries, object.TreeEntry{
		Name: KeysDir,
		Mode: filemode.Dir,
		Hash: keysTreeHash,
	})

	treeHash, err := writeTree(s.repository, topLevelEntries)
	if err != nil {
		return err
	}
	s.tree = treeHash

	// Commit to ref
	commitHash, err := commit(s.repository, s.tip, treeHash, PolicyStateRef)
	if err != nil {
		return err
	}
	s.tip = commitHash

	s.written = true

	return nil
}

func (s *PolicyState) RemoveMetadata(roleNames []string) error {
	s.written = false

	for _, role := range roleNames {
		delete(s.metadataStaging, role)
		delete(s.metadataIdentifiers, role)
	}

	return s.Commit()
}

func (s *PolicyState) RemoveKeys(keyIDs []string) error {
	s.written = false

	for _, keyID := range keyIDs {
		delete(s.keysStaging, keyID)
		delete(s.rootKeys, keyID)
	}
	return s.Commit()
}
