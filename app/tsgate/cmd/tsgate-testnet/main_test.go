package main

import (
	"bytes"
	"testing"
)

func TestParseSSH(t *testing.T) {
	for _, test := range []struct {
		name, text, command, input string
		pty                        bool
	}{
		{"command", `"whoami --json"`, "whoami --json", "", false},
		{"stdin", `"cp - vm:/root/x" "line\n\u0000tail"`, "cp - vm:/root/x", "line\n\x00tail", false},
		{"pty", `"shell vm" pty`, "shell vm", "", true},
		{"stdin_pty", `"shell vm" "exit\n" pty`, "shell vm", "exit\n", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := parseSSH(test.text)
			if err != nil {
				t.Fatal(err)
			}
			if request.command != test.command || request.input != test.input || request.pty != test.pty {
				t.Fatalf("unexpected request: %#v", request)
			}
		})
	}
	for _, text := range []string{"", "whoami", `null`, `""`, `"unterminated`, `"cmd" invalid`, `"cmd" "input" "extra"`, `"cmd" "bad\q"`, `"cmd" pty extra`} {
		if _, err := parseSSH(text); err == nil {
			t.Errorf("accepted malformed request %q", text)
		}
	}
}

func TestSSHOutputIsBounded(t *testing.T) {
	var output limitedBuffer
	if n, err := output.Write(bytes.Repeat([]byte{'x'}, 1<<20)); err != nil || n != 1<<20 {
		t.Fatalf("limit-sized write: n=%d, err=%v", n, err)
	}
	if n, err := output.Write([]byte{'x'}); err == nil || n != 0 {
		t.Fatalf("overflow write: n=%d, err=%v", n, err)
	}
	if output.Len() != 1<<20 {
		t.Fatalf("output grew beyond limit: %d", output.Len())
	}
}
