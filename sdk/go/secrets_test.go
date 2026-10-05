package silo

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeMachineScopedSecrets(t *testing.T) {
	root := os.Getenv("SILO_TEST_RUNTIME_ROOT")
	if root == "" {
		t.Skip("native runtime required")
	}
	home := t.TempDir()
	ctx := context.Background()
	r, err := Open(ctx, WithHome(home), WithRuntimeRoot(root))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	disk := filepath.Join(home, "input.raw")
	if err = os.WriteFile(disk, []byte("stopped fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := r.CreateMachine(ctx, DiskImage(disk), WithName("secret-vm"))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	const key = "tailscale.vm.auth_key"
	if err = m.SetSecret(ctx, key, []byte("scoped-key")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(home, "machines", m.ID(), "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	var records map[string]json.RawMessage
	if err = json.Unmarshal(raw, &records); err != nil {
		t.Fatal(err)
	}
	var saved struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	if err = json.Unmarshal(records[key], &saved); err != nil || saved.Type != "plain" || saved.Value != "scoped-key" {
		t.Fatal("wrong scope or value", err)
	}
	if err = m.DeleteSecret(ctx, key); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join(home, "machines", m.ID(), "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	clear(records)
	if err = json.Unmarshal(raw, &records); err != nil {
		t.Fatal(err)
	}
	if _, exists := records[key]; exists {
		t.Fatal("secret not deleted")
	}
	if err = m.SetSecret(ctx, "silo.ssh_ca.private_key", []byte("replaced")); err == nil {
		t.Fatal("infrastructure key overwritten")
	}
	if err = m.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if err = m.SetSecret(ctx, key, []byte("late")); !IsErrorKind(err, ErrorClosed) {
		t.Fatal(err)
	}
}
