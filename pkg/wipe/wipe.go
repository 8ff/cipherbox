package wipe

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type FileInfo struct {
	ModTime time.Time
	Perm    fs.FileMode
	Size    int64
	IsDir   bool
	Path    string
}

func ListLocalTree(p string) ([]FileInfo, error) {
	list := make([]FileInfo, 0)
	err := filepath.Walk(p,
		func(path string, i os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			list = append(list, FileInfo{ModTime: i.ModTime(), Size: i.Size(), IsDir: i.IsDir(), Path: path, Perm: i.Mode().Perm()})
			return nil
		})
	if err != nil {
		return nil, err
	}

	return list, nil
}

func RandSha256() string {
	r := make([]byte, 10)
	rand.Read(r)
	h := sha256.New()
	h.Write(r)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func SliceHas_string(s []string, n string) bool {
	for _, d := range s {
		if d == n {
			return true
		}
	}
	return false
}

func Wipe(basePath string, numPasses int) error {
	tmpTree, err := ListLocalTree(basePath)
	if err != nil {
		return err
	}
	if len(tmpTree) == 0 {
		return fmt.Errorf("directory empty")
	}
	tree := make([]FileInfo, 0)
	prev := make([]string, 0)

	// Sort files
	for {
		longestDirNum := 0
		longestDirIndex := 0
		for f := range tmpTree {
			dirLen := len(strings.Split(tmpTree[f].Path, "/"))
			if dirLen > longestDirNum && !SliceHas_string(prev, tmpTree[f].Path) {
				longestDirNum = dirLen
				longestDirIndex = f
			}
		}

		prev = append(prev, tmpTree[longestDirIndex].Path)
		tree = append(tree, tmpTree[longestDirIndex])
		if len(tmpTree) == len(tree) {
			break
		}
	}

	// Overwrite files
	passesDone := 0
	for {
		for f := range tree {
			if tree[f].Path == basePath {
				continue
			} // Skip base basePath
			if !tree[f].IsDir {
				lastPos := 0
				const chunkSize = 1 * (1 << 20) // 1 MB
				chunkBytes := make([]byte, chunkSize)
				totalParts := int64(math.Ceil(float64(tree[f].Size) / float64(chunkSize)))
				for i := int64(0); i < totalParts; i++ {
					rand.Read(chunkBytes)
					file, e := os.OpenFile(tree[f].Path, os.O_RDWR, tree[f].Perm)
					if e != nil {
						return e
					}
					if _, err := file.WriteAt(chunkBytes, int64(lastPos)); err != nil {
						return e
					}
					lastPos = lastPos + chunkSize
				}

			}
		}
		passesDone++
		if passesDone == numPasses {
			break
		}
	}

	// Rename everything
	for f := range tree {
		if tree[f].Path == basePath {
			continue
		} // Skip base basePath
		dir, _ := filepath.Split(tree[f].Path)
		newPath := fmt.Sprintf("%s%s", dir, RandSha256())
		if e := os.Rename(tree[f].Path, newPath); e != nil {
			return e
		}
	}

	if e := os.RemoveAll(basePath); e != nil {
		return e
	}
	return nil
}
