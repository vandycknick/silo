package sshd

import (
	"bytes"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/state"
	silo "github.com/vandycknick/silo/sdk/go"
)

func TestRenderingSnapshots(t *testing.T) {
	v := service.VM{ID: "vm", Name: "dev", Owner: "user:1", State: silo.MachineStatusStopped, CPUs: 2, Memory: 4096, Disk: 8192, Created: time.Unix(0, 0).UTC(), Image: "ghcr.io/ns/image:tag", Labels: map[string]string{"team": "alpha"}, LastOperation: &jobs.Operation{ID: "op_00000000000000000000000000", State: "succeeded"}}
	if got := renderList([]service.VM{v}); got != "NAME STATE NODE ADDRESS CPUS MEMORY CREATED\ndev stopped   2 4096 1970-01-01T00:00:00Z\n" {
		t.Fatal(got)
	}
	want := "Name: dev\nID: vm\nOwner: user:1\nState: stopped\nCPUs: 2\nMemory: 4096\nDisk: 8192\nImage: ghcr.io/ns/image:tag\nLabels: map[team:alpha]\nLast operation: op_00000000000000000000000000 succeeded\n"
	want += "Node: \nNode state: \nAddress: \nKey expiry: \n"
	if got := renderShow(v); got != want {
		t.Fatal(got)
	}
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

func TestStreamingDelimiterAndCommandHelp(t *testing.T) {
	tokens, e := Tokenize(`exec dev -- /bin/printf '%s' --json '--yes' '$HOME; | literal'`)
	if e != nil || len(tokens) != 8 {
		t.Fatal(tokens, e)
	}
	if tokens[5] != "--json" || tokens[6] != "--yes" || tokens[7] != "$HOME; | literal" {
		t.Fatal(tokens)
	}
	for _, cmd := range []string{"create", "ls", "show", "start", "stop", "restart", "reauth", "rm", "set", "shell", "exec", "logs", "ops", "whoami"} {
		if _, ok := commandHelp(cmd); !ok {
			t.Fatal("command missing help", cmd)
		}
	}
}
