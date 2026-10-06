package sshd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
)

// The grammar is exercised below authentication with a verified peer that
// holds no grants and a service without a runtime or job registry. A line the
// parser rejects exits 2 before any domain call. A line the parser accepts
// reaches authorization, which refuses the grantless peer with exit 4; had a
// malformed request slipped through, the nil runtime would panic instead.
func TestCommandGrammar(t *testing.T) {
	audit := offlineAudit(t)
	s := &service.Service{Audit: audit, Capability: "cap", Config: testfixture.Config()}
	peer := identity.Peer{Principals: []identity.Principal{"tag:ci"}, NodeID: "grammar", NodeName: "ci", ObservedAt: time.Now()}
	caller := service.Caller{Peer: peer}
	terminal := service.Terminal{Present: true, Window: service.Window{Rows: 24, Columns: 80}}
	for _, tc := range []struct {
		line string
		exit int
	}{
		// Session-wide flags and the tokenizer.
		{"", 2}, {"unknown", 2}, {"ls | cat", 2}, {"--json --json ls", 2}, {"--yes ls", 2}, {"ls --json", 4},
		{"rm vm --yes --yes", 2}, {"stop vm -- x", 2}, {"ls -- x", 2},
		{"rm vm --yes --yes=false", 2}, {"rm vm --yes=false --yes", 2}, {"--yes rm vm --yes=false", 2}, {"--yes=false rm vm --yes", 2},
		{"--yes=false rm vm", 4}, {"--yes=true rm vm", 4}, {"rm vm --yes=false --json", 4},
		// Help flags anywhere before the delimiter; values of declared options are never flags.
		{"-h", 0}, {"--help", 0}, {"-h bogus", 2}, {"stop vm --help", 0}, {"exec vm -h -- ls", 0}, {"template -h", 0}, {"template create -h", 0},
		{"create --name x -h", 0}, {"create --name x --userdata -h", 4}, {"exec vm -- -h", 4},
		{"template --owner tag:ci create --help", 0}, {"policy --owner tag:ci create --help", 0},
		{"template --owner tag:ci bogus --help", 2}, {"policy --owner --help bogus --help", 2},
		{"template --owner tag:ci --help", 0}, {"create --userdata -- --help", 0},
		// Aliases resolve only in command position.
		{"list", 4}, {"new dev", 4}, {"status", 2}, {"ssh", 2}, {"help list", 0},
		// Meta commands.
		{"help", 0}, {"help create", 0}, {"help nope", 2}, {"help a b", 2}, {"version", 0}, {"version extra", 2}, {"whoami", 0}, {"whoami x", 2},
		// Queries.
		{"ls extra", 2}, {"ls", 4}, {"show", 2}, {"show a b", 2}, {"ops", 4}, {"ops show", 2}, {"ops list", 2}, {"ops show op_1", 4},
		// create: positionals, once-only flags, shared --disk/--disk-size budget, repeatable --label.
		{"create", 4}, {"create --cpus 2 dev", 4}, {"create dev img --image other", 2}, {"create dev img extra", 2},
		{"create dev --cpus", 2}, {"create dev --cpus 0", 2}, {"create dev --cpus x", 2}, {"create dev --cpus 2 --cpus 2", 2},
		{"create dev --memory 1GiB --memory 1GiB", 2}, {"create dev --memory 0", 4}, {"create dev --disk 1GiB --disk-size 2GiB", 2},
		{"create dev --template ''", 2}, {"create dev --image ''", 2}, {"create dev --policy ''", 2}, {"create dev --bogus", 2},
		{"create dev --label a", 2}, {"create dev --label a=1 --label a=2", 2}, {"create dev --provision-user nope", 2},
		{"create dev --no-start --no-start", 2}, {"create dev --timeout 1s", 2},
		{"create dev", 4}, {"create --name dev img", 4}, {"create --name dev --image img --cpus 2 --memory 512MiB --disk-size 1GiB --tailscale --no-start", 4}, {"create --no-tailnet", 2},
		{"create dev --label a=1 --label b=2 --owner tag:ci --template t --policy p --userdata '#!/bin/sh'", 4}, {"create dev --userdata -", 4},
		// Single-argument mutations.
		{"start", 2}, {"start a b", 2}, {"restart", 2}, {"reauth a --force", 2},
		{"stop", 2}, {"stop vm --timeout", 2}, {"stop vm --timeout soon", 2}, {"stop vm --force --force", 2}, {"stop vm --bogus", 2},
		{"rm", 2}, {"rm vm extra", 2}, {"rm vm --force --force", 2},
		{"set vm", 2}, {"set vm cpus", 2}, {"set vm cpus=0", 2}, {"set vm cpus=300", 2}, {"set vm cpus=2 cpus=3", 2}, {"set vm bogus=1", 2},
		// Streams refuse --json and have their own short flags.
		{"shell", 2}, {"shell vm --json", 2}, {"shell vm -w /", 2}, {"shell vm -u", 2}, {"shell vm -u root", 4}, {"shell vm", 4},
		{"exec vm", 2}, {"exec vm --", 2}, {"exec vm -u -- cmd", 2}, {"exec vm -e NOEQ -- cmd", 2}, {"exec vm -x 1 -- cmd", 2}, {"exec vm cmd", 2}, {"exec vm --json -- cmd", 2},
		{"exec vm -- cmd --json", 4}, {"exec vm -t -u root -w / -e A=1 -e B=2 -- /bin/sh -c 'printf x'", 4},
		{"logs", 2}, {"logs vm --json", 2}, {"logs vm --stream", 2}, {"logs vm --output stdout --output stderr", 2}, {"logs vm extra", 2},
		{"logs vm --follow --stream network-audit --output stderr", 4},
		// Documents: verb-dependent positionals, one owner flag, stdin only after authorization.
		{"template", 2}, {"template bogus", 2}, {"template show", 2}, {"template ls extra", 2}, {"template ls --owner", 2}, {"template ls --owner tag:ci --owner tag:ci", 2},
		{"template ls", 4}, {"template show name --owner tag:ci", 4}, {"template create name", 4}, {"template validate", 4}, {"policy rm name", 4}, {"policy validate --owner tag:ci", 4},
	} {
		var out, human bytes.Buffer
		code := DispatchSession(t.Context(), s, caller, tc.line, service.IO{Stdout: &out, Stderr: &human, Terminal: terminal})
		if code != tc.exit {
			t.Fatalf("%q: exit %d, want %d: %s%s", tc.line, code, tc.exit, out.String(), human.String())
		}
		if strings.Contains(tc.line, "--json") && !strings.HasSuffix(tc.line, "-- cmd --json") && tc.exit != 2 && !strings.HasPrefix(out.String(), `{"ok":`) {
			t.Fatalf("%q: missing JSON envelope: %q", tc.line, out.String())
		}
	}
}
