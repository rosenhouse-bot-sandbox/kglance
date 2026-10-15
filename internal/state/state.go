// Package state records what kglance setup created so teardown can verify and remove it.
package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

const (
	Version      = 1
	RoleMgmt     = "mgmt"
	RoleWorkload = "workload"
)

type File struct {
	Version    int       `json:"version"`
	Kubeconfig string    `json:"kubeconfig"`
	Expiry     time.Time `json:"expiry"`
	Clusters   []Cluster `json:"clusters"`
}

type Cluster struct {
	Name          string   `json:"name"`
	Role          string   `json:"role"`
	Context       string   `json:"context"`
	Server        string   `json:"server"`
	CAFingerprint string   `json:"caFingerprint"`
	Objects       []Object `json:"objects"`
}

type Object struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
}

func (f *File) Find(name string) *Cluster {
	for i := range f.Clusters {
		if f.Clusters[i].Name == name {
			return &f.Clusters[i]
		}
	}
	return nil
}

func (f *File) Put(c Cluster) {
	if old := f.Find(c.Name); old != nil {
		*old = c
		return
	}
	f.Clusters = append(f.Clusters, c)
}

// Fingerprint returns the sha256 hex of the first certificate's DER in a PEM bundle, or "" for no CA.
func Fingerprint(caPEM []byte) (string, error) {
	if len(caPEM) == 0 {
		return "", nil
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return "", errors.New("CA data is not PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

// Load returns an empty state when path does not exist.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &File{Version: Version}, nil
	}
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if f.Version != Version {
		return nil, fmt.Errorf("%s: unsupported version %d", path, f.Version)
	}
	return &f, nil
}

func Save(path string, f *File) error {
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, append(raw, '\n'))
}

// WriteFileAtomic writes data with mode 0600 via a temp file and rename.
func WriteFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
