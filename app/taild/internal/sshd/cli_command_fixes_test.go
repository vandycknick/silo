package sshd

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/service"
)

func TestCLIYesFalseOpenSSHNative(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	s, caller, registry := nativeService(t, ctx, "yes-parser", "user:7")
	removalDispatch(t, ctx, s, caller, "create --name devbox --no-start", 0)
	address := terminalSSHServer(t, s, caller)
	for _, line := range []string{
		"rm devbox --yes=false", "--yes=false rm devbox", "-yes=false rm devbox --json",
		"rm devbox --yes=0", "rm devbox --json",
	} {
		// A leading space keeps OpenSSH's getopt from treating a remote
		// leading option as an option to ssh itself.
		c := openRemovalClient(t, ctx, address, " "+line)
		c.prompt(t, "Remove VM 'devbox'? [y/N] ", 1)
		c.send(t, "no\n")
		c.exit(t, 2, strings.Contains(line, "--json"))
		if _, err := s.Show(ctx, caller.Peer, "devbox"); err != nil {
			t.Fatal(line, err)
		}
	}
	beforeJobs, beforeRequests := len(s.Jobs.List(caller.Peer)), registry.Requests.Load()
	for _, line := range []string{
		"rm devbox --yes --yes=false", "rm devbox --yes=false --yes",
		"--yes rm devbox --yes=false", "--yes=false rm devbox --yes",
		"--yes=true --yes=false rm devbox --json",
	} {
		out, diagnostic, code := sshPipeCommand(t, address, " "+line, nil, false)
		if code != 2 || !bytes.Contains(diagnostic, []byte("duplicate option")) || bytes.Contains(diagnostic, []byte("[y/N]")) {
			t.Fatal(line, code, string(out), string(diagnostic))
		}
	}
	if len(s.Jobs.List(caller.Peer)) != beforeJobs || registry.Requests.Load() != beforeRequests {
		t.Fatal("invalid consent started work")
	}
	removalDispatch(t, ctx, s, caller, "--yes=true rm devbox", 0)
	if _, err := s.Show(ctx, caller.Peer, "devbox"); service.Categorize(err).Exit != 3 {
		t.Fatal("inline true did not remove VM", err)
	}
}

func TestCLILogDefaultsActualSerialFile(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	s, caller, _ := nativeService(t, ctx, "logs-default", "user:7")
	removalDispatch(t, ctx, s, caller, "create --name devbox --no-start", 0)
	view, err := s.Show(ctx, caller.Peer, "devbox")
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(s.Config.Home, "logs", "machines", view.ID)
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"serial.log": "serial-default-line\n", "trace.log": "monitor-other-line\n"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ line, want string }{
		{"logs devbox", "serial-default-line\n"},
		{"logs devbox --stream serial", "serial-default-line\n"},
		{"logs devbox --output stdout", "serial-default-line\n"},
		{"logs devbox --output stderr", ""},
	} {
		var out, diagnostic bytes.Buffer
		if code := DispatchSession(ctx, s, caller, tc.line, service.IO{Stdout: &out, Stderr: &diagnostic}); code != 0 || out.String() != tc.want {
			t.Fatal(tc.line, code, out.String(), diagnostic.String())
		}
	}
	var help bytes.Buffer
	if code := DispatchSession(ctx, s, caller, "logs --help", service.IO{Stdout: io.Discard, Stderr: &help}); code != 0 || !strings.Contains(help.String(), "default: serial") || !strings.Contains(help.String(), "default: all") {
		t.Fatal(code, help.String())
	}
}
