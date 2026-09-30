package sshd

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/state"
)

func TestTokenizer(t *testing.T) {
	for _, tt := range []struct {
		line    string
		want    []string
		invalid bool
	}{
		{"", nil, false}, {"whoami --json", []string{"whoami", "--json"}, false}, {`a '' ""`, []string{"a", "", ""}, false}, {`a 'two words' "three words"`, []string{"a", "two words", "three words"}, false}, {`a\ b "x\"y"`, []string{"a b", `x"y`}, false}, {`a "x\qy"`, []string{"a", `x\qy`}, false}, {`a '$HOME'`, []string{"a", "$HOME"}, false}, {`a $HOME`, nil, true}, {`a; b`, nil, true}, {`a | b`, nil, true}, {"a\nb", nil, true}, {`'open`, nil, true}, {`a\`, nil, true},
	} {
		got, e := Tokenize(tt.line)
		if (e != nil) != tt.invalid {
			t.Fatalf("%q: %v", tt.line, e)
		}
		if !tt.invalid {
			if len(got) != len(tt.want) {
				t.Fatalf("%q: %q", tt.line, got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("%q: %q", tt.line, got)
				}
			}
		}
	}
}
func TestLocalCommandDispatchBelowAuthentication(t *testing.T) {
	audit, e := state.OpenAudit(t.TempDir(), 4096, 2)
	if e != nil {
		t.Fatal(e)
	}
	defer audit.Close()
	s := &service.Service{Audit: audit, Capability: "cap"}
	p := identity.Peer{Principals: []identity.Principal{"user:123"}, NodeID: "node", NodeName: "peer", ObservedAt: time.Now(), Permissions: identity.Permissions{Reason: "No capability"}}
	for _, line := range []string{"whoami --json", "version --json", "help --json", "unknown --json", "whoami --bad --json"} {
		var out, errOut bytes.Buffer
		code := Dispatch(s, p, line, &out, &errOut)
		if line == "whoami --json" && code != 0 {
			t.Fatal(code)
		}
		d := json.NewDecoder(&out)
		var v map[string]json.RawMessage
		if e := d.Decode(&v); e != nil {
			t.Fatal(e)
		}
		if _, ok := v["ok"]; !ok {
			t.Fatal("missing ok")
		}
		if e := d.Decode(&v); e != io.EOF {
			t.Fatal("more than one object")
		}
	}
	var out, errOut bytes.Buffer
	if code := Dispatch(s, p, "whoami", &out, &errOut); code != 0 || out.Len() != 0 || errOut.Len() == 0 {
		t.Fatal("human stream contract")
	}
	if code := Dispatch(s, identity.Peer{}, "whoami", &out, &errOut); code != 4 {
		t.Fatal("identity required")
	}
}
