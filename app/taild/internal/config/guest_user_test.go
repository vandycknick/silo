package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuestUserConfigMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	for _, value := range []string{"{}", "{name: nickvd, uid: 1000, gid: 1000, home: /home/nickvd}", "null"} {
		if err := os.WriteFile(path, []byte("vm:\n  guest_user: "+value+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "--provision-user NAME:UID:GID:HOME") {
			t.Fatal(err)
		}
	}
	if err := Defaults().Validate(); err != nil {
		t.Fatal(err)
	}
}
