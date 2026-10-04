package sshd

import (
	"bytes"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/state"
)

func TestUnknownCommandEnvelope(t *testing.T) {
	audit, e := state.OpenAudit(t.TempDir(), 4096, 2)
	if e != nil {
		t.Fatal(e)
	}
	defer audit.Close()
	s := &service.Service{Audit: audit}
	p := identity.Peer{Principals: []identity.Principal{"user:1"}, NodeID: "explicit-domain", ObservedAt: time.Now()}
	var out, stderr bytes.Buffer
	if code := Dispatch(s, p, "unknown --json", &out, &stderr); code != 2 {
		t.Fatal(code)
	}
	if out.String() != "{\"ok\":false,\"error\":{\"code\":\"usage\",\"message\":\"invalid command arguments; see help\"}}\n" || stderr.String() != "Error: invalid command arguments; see help\n" {
		t.Fatal(out.String(), stderr.String())
	}
}

func TestStreamingDelimiterTokens(t *testing.T) {
	tokens, e := Tokenize(`exec dev -- /bin/printf '%s' --json '--yes' '$HOME; | literal'`)
	if e != nil || len(tokens) != 8 {
		t.Fatal(tokens, e)
	}
	if tokens[5] != "--json" || tokens[6] != "--yes" || tokens[7] != "$HOME; | literal" {
		t.Fatal(tokens)
	}
}
