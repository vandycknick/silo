package sshd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/service"
)

func TestActualSDKCRLFCommandRemovalConfirmation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, caller, registry := nativeService(t, "crlf-native", "user:7")
	p := caller.Peer
	var diagnostic bytes.Buffer
	if code := DispatchSession(ctx, s, caller, "create "+registry.Reference+" --name crlf-vm --no-start", service.IO{Stdout: io.Discard, Stderr: &diagnostic}); code != 0 {
		t.Fatal(code, diagnostic.String())
	}
	input := newInput(ctx, strings.NewReader("rm crlf-vm\r\nyes\r\nls --json\r\n"))
	reader := input.Reader(ctx)
	command, e := readLine(reader)
	if e != nil {
		t.Fatal(e)
	}
	diagnostic.Reset()
	streams := service.IO{Stdin: reader, Input: input.Reader, Stdout: io.Discard, Stderr: &diagnostic, Terminal: service.Terminal{Present: true}}
	streams.Prompt = sessionPrompt(streams)
	if code := DispatchSession(ctx, s, caller, command, streams); code != 0 {
		t.Fatal("actual CRLF confirmation rejected", code, diagnostic.String())
	}
	if _, e = s.Show(ctx, p, "crlf-vm"); e == nil || service.Categorize(e).Exit != 3 {
		t.Fatal("confirmed machine was not removed", e)
	}
	command, e = readLine(input.Reader(ctx))
	if e != nil || command != "ls --json" {
		t.Fatal("confirmation left an LF for the next command", command, e)
	}
	var out bytes.Buffer
	if code := DispatchSession(ctx, s, caller, command, service.IO{Stdout: &out, Stderr: io.Discard}); code != 0 || out.String() != "{\"ok\":true,\"data\":[]}\n" {
		t.Fatal(code, out.String())
	}
}

func TestNativeCreateRequiresImageAndHonorsTemplateOverrides(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	s, caller, registry := nativeService(t, "image-admission", "user:7")
	for _, template := range []struct{ name, content string }{
		{"image-free", "version: '1'\nresources: {cpus: 1}"},
		{"with-image", "version: '1'\nimage: " + registry.Reference},
		{"overridden", "version: '1'\nimage: " + strings.Replace(registry.Reference, "/rootfs:", "/missing:", 1)},
	} {
		if _, err := s.Documents(ctx, caller, "template", "create", template.name, "", template.content); err != nil {
			t.Fatal(err)
		}
	}
	for _, line := range []string{
		"create --name missing --no-start",
		"create --template image-free --name missing --no-start",
		"create --name missing --no-start --json",
	} {
		var out, diagnostic bytes.Buffer
		if code := DispatchSession(ctx, s, caller, line, service.IO{Stdout: &out, Stderr: &diagnostic}); code != 2 {
			t.Fatal("missing image accepted", line, code, out.String(), diagnostic.String())
		}
		if strings.HasSuffix(line, "--json") {
			var envelope struct {
				OK    bool `json:"ok"`
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(out.Bytes(), &envelope); err != nil || envelope.OK || envelope.Error.Code != "usage" || !strings.Contains(envelope.Error.Message, "--template") || !strings.Contains(envelope.Error.Message, "--image") {
				t.Fatal("missing image lacked helpful usage", err, out.String())
			}
		} else if !strings.Contains(diagnostic.String(), "--template") || !strings.Contains(diagnostic.String(), "--image") {
			t.Fatal("missing image lacked helpful usage", diagnostic.String())
		}
	}
	if registry.Requests.Load() != 0 || len(s.Jobs.List(caller.Peer)) != 0 {
		t.Fatal("missing image started work", registry.Requests.Load(), s.Jobs.List(caller.Peer))
	}
	entries, err := s.Runtime.Control.Inventory(ctx)
	if err != nil || len(entries) != 0 {
		t.Fatal("missing image created a VM", entries, err)
	}
	for _, request := range []struct{ name, command string }{
		{"templated", "create --template with-image --name templated --no-start"},
		{"positional", "create " + registry.Reference + " --template overridden --name positional --no-start"},
		{"flag", "create --image " + registry.Reference + " --template overridden --name flag --no-start"},
	} {
		var diagnostic bytes.Buffer
		if code := DispatchSession(ctx, s, caller, request.command, service.IO{Stdout: io.Discard, Stderr: &diagnostic}); code != 0 {
			t.Fatal(request.command, code, diagnostic.String())
		}
		data, err := s.Runtime.Control.Inspect(ctx, request.name)
		if err != nil || data.ImageRef != registry.Reference {
			t.Fatal("selected image not materialized", request.name, data, err)
		}
	}
	if registry.Requests.Load() == 0 {
		t.Fatal("successful creation did not use the real OCI registry")
	}
}
