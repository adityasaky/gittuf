package metadata

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	tufdata "github.com/theupdateframework/go-tuf/data"
)

func getNameWithoutExtension(fileName string) string {
	knownFileTypes := []string{".json", ".pub"}
	for _, t := range knownFileTypes {
		if strings.HasSuffix(fileName, t) {
			return strings.TrimSuffix(fileName, t)
		}
	}
	return fileName
}

/*
initPolicyState is invoked during the init workflow. A set of TUF metadata is
created and passed in. This is then written to the store.
*/
func initPolicyState(repo *git.Repository, rootPublicKeys []tufdata.PublicKey, metadata map[string][]byte) (*PolicyState, error) {
	r := &PolicyState{
		metadataStaging:     map[string][]byte{},
		keysStaging:         map[string][]byte{},
		tip:                 plumbing.ZeroHash,
		tree:                plumbing.ZeroHash,
		repository:          repo,
		metadataIdentifiers: map[string]object.TreeEntry{},
		rootKeys:            map[string]object.TreeEntry{},
		written:             false,
	}

	err := r.StageKeys(rootPublicKeys)
	if err != nil {
		return &PolicyState{}, err
	}

	r.StageMultipleMetadata(metadata)

	return r, nil
}

func loadState(repo *git.Repository, commitID plumbing.Hash) (*PolicyState, error) {
	commitObj, err := repo.CommitObject(commitID)
	if err != nil {
		return &PolicyState{}, err
	}

	tree, err := repo.TreeObject(commitObj.TreeHash)
	if err != nil {
		return &PolicyState{}, err
	}

	var metadataTree *object.Tree
	var keysTree *object.Tree

	for _, entry := range tree.Entries {
		if entry.Name == MetadataDir {
			metadataTree, err = repo.TreeObject(entry.Hash)
			if err != nil {
				return &PolicyState{}, err
			}
		} else if entry.Name == KeysDir {
			keysTree, err = repo.TreeObject(entry.Hash)
			if err != nil {
				return &PolicyState{}, err
			}
		}
	}

	metadataIdentifiers := map[string]object.TreeEntry{}
	for _, entry := range metadataTree.Entries {
		metadataIdentifiers[getNameWithoutExtension(entry.Name)] = entry
	}

	rootKeys := map[string]object.TreeEntry{}
	for _, entry := range keysTree.Entries {
		rootKeys[getNameWithoutExtension(entry.Name)] = entry
	}

	return &PolicyState{
		metadataStaging:     map[string][]byte{},
		keysStaging:         map[string][]byte{},
		repository:          repo,
		tip:                 commitObj.Hash,
		tree:                commitObj.TreeHash,
		metadataIdentifiers: metadataIdentifiers,
		rootKeys:            rootKeys,
		written:             true,
	}, nil
}

func writeBlob(repo *git.Repository, contents []byte) (plumbing.Hash, error) {
	obj := repo.Storer.NewEncodedObject()
	obj.SetType(plumbing.BlobObject)
	writer, err := obj.Writer()
	if err != nil {
		return plumbing.ZeroHash, err
	}
	_, err = writer.Write(contents)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	return repo.Storer.SetEncodedObject(obj)
}

func readBlob(repo *git.Repository, blobHash plumbing.Hash) (int, []byte, error) {
	blob, err := repo.BlobObject(blobHash)
	if err != nil {
		return -1, []byte{}, err
	}
	contents := make([]byte, blob.Size)
	reader, err := blob.Reader()
	if err != nil {
		return -1, []byte{}, err
	}
	length, err := reader.Read(contents)
	if err != nil {
		return -1, []byte{}, err
	}
	return length, contents, nil
}

func writeTree(repo *git.Repository, entries []object.TreeEntry) (plumbing.Hash, error) {
	sort.Slice(entries, func(i int, j int) bool {
		return entries[i].Name < entries[j].Name
	})
	obj := repo.Storer.NewEncodedObject()
	tree := object.Tree{
		Entries: entries,
	}
	err := tree.Encode(obj)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	return repo.Storer.SetEncodedObject(obj)
}

func commit(repo *git.Repository, parent plumbing.Hash, treeHash plumbing.Hash, targetRef string) (plumbing.Hash, error) {
	gitConfig, err := repo.ConfigScoped(config.GlobalScope)
	if err != nil {
		return plumbing.ZeroHash, err
	}

	curRef, err := repo.Reference(plumbing.ReferenceName(targetRef), true)
	if err != nil {
		return plumbing.ZeroHash, err
	}

	author := object.Signature{
		Name:  gitConfig.User.Name,
		Email: gitConfig.User.Email,
		When:  time.Now(),
	}

	commit := object.Commit{
		Author:    author,
		Committer: author,
		TreeHash:  treeHash,
		Message:   fmt.Sprintf("gittuf: Writing state tree %s", treeHash.String()),
	}
	if parent != plumbing.ZeroHash {
		commit.ParentHashes = []plumbing.Hash{parent}
	}

	obj := repo.Storer.NewEncodedObject()
	err = commit.Encode(obj)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	commitHash, err := repo.Storer.SetEncodedObject(obj)
	if err != nil {
		return plumbing.ZeroHash, err
	}

	newRef := plumbing.NewHashReference(plumbing.ReferenceName(targetRef), commitHash)
	err = repo.Storer.CheckAndSetReference(newRef, curRef)
	return commitHash, err
}
