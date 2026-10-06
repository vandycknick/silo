package control

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestControlEndpointRejectsUnsafeReplacement(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	endpoint := filepath.Join(root, "control.sock")
	listener, err := net.Listen("unix", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := os.Chmod(endpoint, 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateEndpoint(endpoint); err != nil {
		t.Fatalf("owned private socket rejected: %v", err)
	}
	if err := os.Chmod(endpoint, 0660); err != nil {
		t.Fatal(err)
	}
	if err := validateEndpoint(endpoint); err == nil {
		t.Fatal("group-accessible socket admitted")
	}
	if err := os.Chmod(endpoint, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := validateEndpoint(endpoint); err == nil {
		t.Fatal("nonprivate parent admitted")
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias.sock")
	if err := os.Symlink(endpoint, alias); err != nil {
		t.Fatal(err)
	}
	if err := validateEndpoint(alias); err == nil {
		t.Fatal("symlink socket admitted")
	}
	regular := filepath.Join(root, "regular")
	if err := os.WriteFile(regular, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateEndpoint(regular); err == nil {
		t.Fatal("regular file admitted as socket")
	}
}
