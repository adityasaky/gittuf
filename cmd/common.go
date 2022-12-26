package cmd

import (
	"strconv"
	"time"

	"github.com/adityasaky/gittuf/gittuf"
	metadata "github.com/adityasaky/gittuf/internal/gittuf-metadata"
	tufdata "github.com/theupdateframework/go-tuf/data"
)

var (
	role         string
	roleKeyPaths []string
	long         bool
)

// Borrowed from go-tuf
func parseExpires(e string, role string) (time.Time, error) {
	if len(e) == 0 {
		return tufdata.DefaultExpires(role), nil
	}
	days, err := strconv.Atoi(e)
	if err != nil {
		return time.Time{}, err
	}
	return time.Now().AddDate(0, 0, days).UTC(), nil
}

func getGitTUFMetadataHandler() (*metadata.GitTUFMetadata, error) {
	dir, err := gittuf.GetRepoRootDir()
	if err != nil {
		return &metadata.GitTUFMetadata{}, err
	}
	return metadata.LoadGitTUFMetadataHandler(dir)
}
