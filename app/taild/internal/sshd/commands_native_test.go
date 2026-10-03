package sshd

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/service"
)

func TestActualSDKCRLFCommandRemovalConfirmation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, caller, _ := nativeService(t, ctx, "crlf-native", "user:7")
	p := caller.Peer
	var diagnostic bytes.Buffer
	if code := DispatchSession(ctx, s, caller, "create --name crlf-vm --no-start", service.IO{Stdout: io.Discard, Stderr: &diagnostic}); code != 0 {
		t.Fatal(code, diagnostic.String())
	}
	input := newInput(ctx, strings.NewReader("rm crlf-vm\r\nyes\r\nls --json\r\n"))
	reader := input.Reader(ctx)
	command, e := readLine(reader)
	if e != nil {
		t.Fatal(e)
	}
	diagnostic.Reset()
	if code := DispatchSession(ctx, s, caller, command, service.IO{Stdin: reader, Input: input.Reader, Stdout: io.Discard, Stderr: &diagnostic, Terminal: service.Terminal{Present: true}}); code != 0 {
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
