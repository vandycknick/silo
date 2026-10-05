package state

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

// Historical transaction writers are test fixtures for crash recovery only.
func BeginNodeTransaction(dir string) error {
	f, err := os.OpenFile(dir+".transaction", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.WriteString("node-state-v1\n")
	return errors.Join(err, f.Sync(), f.Close(), SyncDir(filepath.Dir(dir)))
}

func MarkVerifiedNode(dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, "tailscaled.state"))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	f, err := os.OpenFile(filepath.Join(dir, "promotion.verified"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(hex.EncodeToString(sum[:]))
	return errors.Join(err, f.Sync(), f.Close(), SyncDir(dir))
}
