package commands

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/service"
)

func TestJSONAwaitPublishesPrebootConsentOnHumanStream(t *testing.T) {
	r := jobs.New(t.Context(), 1)
	op, err := r.Submit("create", "vm", "user:7", func(_ context.Context, progress func(string)) error {
		progress("approve: https://login.tailscale.com/a/example")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var human, stdout bytes.Buffer
	c := &Context{Context: t.Context(), JSON: true, Service: &service.Service{Jobs: r}, Caller: service.Caller{Peer: identity.Peer{Principals: []identity.Principal{"user:7"}}}, Streams: service.IO{Stdout: &stdout, Human: &human}}
	if _, err := c.Await(op, nil); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 || human.String() != "approve: https://login.tailscale.com/a/example\n" {
		t.Fatal(stdout.String(), human.String())
	}
}

func TestProgressAnimationAndCompletion(t *testing.T) {
	var out bytes.Buffer
	p := progressDisplay{out: &out, animated: true, width: 20, message: phase("pulling ghcr.io/long/image:latest", "dev")}
	if err := p.tick(); err != nil {
		t.Fatal(err)
	}
	first := out.String()
	if !strings.Contains(first, "⠋ Pulling") || len([]rune(strings.TrimPrefix(first, "\r\x1b[2K"))) >= 20 {
		t.Fatal(first)
	}
	out.Reset()
	p.width = 10
	if err := p.tick(); err != nil {
		t.Fatal(err)
	}
	if err := p.clear(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out.String(), "\r\x1b[2K") || p.visible {
		t.Fatal(out.String())
	}
	out.Reset()
	p.animated = false
	if err := p.tick(); err != nil || out.Len() != 0 {
		t.Fatal("nonterminal animation", out.String(), err)
	}
	now := time.Now()
	end := now.Add(2400 * time.Millisecond)
	op := jobs.Operation{Kind: "create", VM: "dev", Started: now, Finished: &end, Completion: &jobs.Completion{Name: "dev", Running: true, User: "root", NodeState: "approval_required", ApprovalURL: "https://login.tailscale.com/a/example"}}
	text := completionText(op, "silo")
	for _, want := range []string{"✓ Ready", "dev (2.4s)", "ssh -t silo shell dev", op.Completion.ApprovalURL} {
		if !strings.Contains(text, want) {
			t.Fatal(text, want)
		}
	}
	if strings.Contains(text, "ssh root@") {
		t.Fatal("pending direct SSH advertised")
	}
	op.Completion.ApprovalURL = ""
	op.Completion.NodeState = "enrolled"
	op.Completion.Node = "dev.tail.test"
	op.Completion.User = "alice"
	if text = completionText(op, "silo"); !strings.Contains(text, "ssh alice@dev.tail.test") {
		t.Fatal(text)
	}
	op.Completion.Running = false
	if text = completionText(op, "silo"); strings.Contains(text, "Ready") || strings.Contains(text, "\nShell") || !strings.Contains(text, "ssh silo start dev") {
		t.Fatal(text)
	}
}

func TestAllHelpTopicsUseSharedLayout(t *testing.T) {
	for _, cmd := range all {
		paths := [][]string{{cmd.Name}}
		for _, sub := range cmd.Subcommands {
			paths = append(paths, []string{cmd.Name, sub})
		}
		for _, path := range paths {
			text, ok := detailedHelp(path, nil)
			if !ok {
				t.Fatal(path)
			}
			for _, tokens := range [][]string{append([]string{"help"}, path...), append(append([]string{}, path...), "--help")} {
				result, err := Execute(&Context{}, tokens)
				if err != nil || result.Human != text {
					t.Fatal("help forms disagree", tokens, err, result.Human)
				}
			}
			for _, heading := range []string{"\n\nUsage:\n  ", "\nOptions:\n  ", "\nExamples:\n  "} {
				if !strings.Contains(text, heading) {
					t.Fatal(path, heading, text)
				}
			}
			usage := strings.Split(strings.Split(text, "Usage:\n")[1], "\n")[0]
			if strings.ContainsAny(usage, ";") || strings.Contains(usage, "(requires") || strings.Contains(usage, "ls|show") {
				t.Fatal(path, usage)
			}
		}
		if len(cmd.Subcommands) > 0 {
			text, _ := detailedHelp([]string{cmd.Name}, nil)
			if !strings.Contains(text, "\nCommands:\n") {
				t.Fatal(text)
			}
		}
	}
}
