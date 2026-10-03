package sshd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/vandycknick/silo/app/taild/internal/service"
)

func TestDocumentCommandsActualRuntimeJSONCRUDAndFiniteInput(t *testing.T) {
	ctx := context.Background()
	s, caller, _ := nativeService(t, ctx, "documents-cli", "tag:one", "tag:two")
	run := func(line, input string, want int) string {
		t.Helper()
		var out, err bytes.Buffer
		code := DispatchSession(ctx, s, caller, line, service.IO{Stdin: strings.NewReader(input), Stdout: &out, Stderr: &err})
		if code != want {
			t.Fatalf("%s exit %d: %s %s", line, code, out.String(), err.String())
		}
		if strings.Contains(line, "--json") {
			var v map[string]json.RawMessage
			if e := json.Unmarshal(out.Bytes(), &v); e != nil {
				t.Fatal(e, out.String())
			}
			if string(v["ok"]) != map[bool]string{true: "true", false: "false"}[want == 0] {
				t.Fatal(out.String())
			}
		}
		return out.String() + err.String()
	}
	for _, kind := range []string{"template", "policy"} {
		raw := "version: '1'"
		if kind == "policy" {
			raw = `settings { default_action = "deny" }`
		}
		run(kind+" create same --json", raw, 2)
		run(kind+" create same --owner tag:one --json", raw, 0)
		run(kind+" create same --owner tag:one --json", raw, 5)
		run(kind+" create same --owner tag:two --json", raw, 0)
		run(kind+" show same --json", "", 2)
		run(kind+" show same --owner tag:foreign --json", "", 4)
		run(kind+" show same --owner tag:one --json", "", 0)
		listed := run(kind+" ls --json", "", 0)
		if !strings.Contains(listed, `"owner":"tag:one"`) || !strings.Contains(listed, `"owner":"tag:two"`) {
			t.Fatal(listed)
		}
		run(kind+" edit same --owner tag:one --json", raw, 0)
		run(kind+" edit absent --owner tag:one --json", raw, 3)
		run(kind+" validate --json", raw, 0)
		run(kind+" validate --json", strings.Repeat("x", service.DocumentLimit+1), 2)
		run(kind+" rm same --owner tag:one --json", "", 0)
		run(kind+" show same --owner tag:one --json", "", 3)
		run(kind+" show same --owner tag:two --json", "", 0)
	}
	// A cancelled session interrupts the production contextual input reader.
	read, write := io.Pipe()
	defer read.Close()
	defer write.Close()
	expired, cancel := context.WithCancel(ctx)
	cancel()
	input := newInput(expired, read)
	if _, e := documentInput(expired, service.IO{Input: input.Reader}, service.DocumentLimit); e == nil {
		t.Fatal("cancelled finite input succeeded")
	}
}
