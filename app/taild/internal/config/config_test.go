package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStrictConfig(t *testing.T) {
	for _, tt := range []struct {
		body  string
		valid bool
	}{{"{}", true}, {"tailnet:\n  hostname: silo-test", true}, {"tailnet:\n  misspelled: true", false}, {"{}\n---\n{}", false}, {"home: relative", false}, {"tailnet:\n  hostname: trailing-", false}, {"vm:\n  defaults: {cpus: 99}", false}, {"tailnet: {hostname: a, hostname: b}", false}, {strings.Repeat(" ", 65537), false}} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if e := os.WriteFile(path, []byte(tt.body), 0600); e != nil {
			t.Fatal(e)
		}
		_, e := Load(path)
		if (e == nil) != tt.valid {
			t.Fatalf("%q: %v", tt.body, e)
		}
	}
}
func TestHomeAndSecrets(t *testing.T) {
	home := t.TempDir()
	if e := os.Chmod(home, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := ResolveHome(home, 0); e == nil {
		t.Fatal("root accepted")
	}
	if os.Geteuid() != 0 {
		if _, e := ResolveHome(home, os.Geteuid()); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := ResolveHome(home, os.Geteuid()+1); e == nil {
		t.Fatal("foreign UID accepted")
	}
	dir := t.TempDir()
	s, e := ReadSecrets(dir)
	if e != nil || s.ClientSecret != "" {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "oauth-client-secret")
	if e = os.WriteFile(path, []byte("synthetic\n"), 0600); e != nil {
		t.Fatal(e)
	}
	s, e = ReadSecrets(dir)
	if e != nil || s.ClientSecret != "synthetic" {
		t.Fatalf("%+v %v", s, e)
	}
	if e = os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadSecrets(dir); e == nil {
		t.Fatal("public secret accepted")
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink("/dev/null", path); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadSecrets(dir); e == nil {
		t.Fatal("symlink secret accepted")
	}
}
