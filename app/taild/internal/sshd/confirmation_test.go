package sshd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/sshd/commands"
)

func TestRemovalConfirmationDecisions(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		want        bool
		prompts     int
	}{
		{"y", "y\n", true, 1}, {"yes", "yes\n", true, 1},
		{"trim-case", " \tYeS \t\n", true, 1}, {"uppercase-y", "Y\n", true, 1},
		{"n", "n\n", false, 1}, {"no", " NO \n", false, 1},
		{"enter", "\n", false, 1}, {"eof", "", false, 1},
		{"partial-eof", "yes", false, 1}, {"ctrl-c", "yes\x03\ny\n", false, 1},
		{"ctrl-d", "\x04", false, 1}, {"invalid-yes", "maybe\nyep\n Y \n", true, 3},
		{"invalid-no", "sure\nno\n", false, 2}, {"invalid-eof", "maybe\n", false, 2},
		{"crlf", "maybe\r\nYES\r\nnext\r\n", true, 2},
	} {
		for _, terminal := range []bool{false, true} {
			t.Run(tc.name+map[bool]string{false: "/pipe", true: "/pty"}[terminal], func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				var out bytes.Buffer
				streams := terminalStreams(ctx, strings.NewReader(tc.input), service.IO{Stderr: &out, Terminal: service.Terminal{Present: terminal}})
				if got := (&commands.Context{Context: ctx, Streams: streams}).Confirm(service.RemovalTarget{Name: "devbox"}); got != tc.want {
					t.Fatalf("got %t, want %t: %q", got, tc.want, out.String())
				}
				if got := strings.Count(out.String(), "Remove VM 'devbox'? [y/N] "); got != tc.prompts {
					t.Fatalf("%d prompts, want %d: %q", got, tc.prompts, out.String())
				}
				if tc.name == "crlf" {
					line, e := readLineLimit(streams.Input(ctx), 1024)
					if e != nil || line != "next" {
						t.Fatal(line, e)
					}
				}
			})
		}
	}
	t.Run("nil", func(t *testing.T) {
		var out bytes.Buffer
		if (&commands.Context{Context: context.Background(), Streams: service.IO{Stderr: &out}}).Confirm(service.RemovalTarget{Name: "devbox"}) || out.Len() != 0 {
			t.Fatal("nil input did not cancel")
		}
	})
	t.Run("running", func(t *testing.T) {
		var out bytes.Buffer
		streams := terminalStreams(t.Context(), strings.NewReader("no\n"), service.IO{Stderr: &out})
		if (&commands.Context{Context: t.Context(), Streams: streams}).Confirm(service.RemovalTarget{Name: "devbox", Running: true}) || out.String() != "Stop and remove VM 'devbox'? [y/N] " {
			t.Fatal(out.String())
		}
	})
	t.Run("stdin-is-not-a-prompter", func(t *testing.T) {
		var out bytes.Buffer
		input := strings.NewReader("yes\n")
		streams := service.IO{Stdin: input, Stderr: &out}
		if (&commands.Context{Context: t.Context(), Streams: streams}).Confirm(service.RemovalTarget{Name: "devbox"}) {
			t.Fatal("confirmation used an implicit stdin reader")
		}
		if input.Len() != len("yes\n") || out.Len() != 0 {
			t.Fatal("missing prompter consumed input or wrote a prompt")
		}
	})
	t.Run("disconnect", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		r, w := io.Pipe()
		defer r.Close()
		defer w.Close()
		streams := terminalStreams(ctx, r, service.IO{Stderr: io.Discard})
		done := make(chan bool, 1)
		go func() {
			done <- (&commands.Context{Context: ctx, Streams: streams}).Confirm(service.RemovalTarget{Name: "devbox"})
		}()
		cancel()
		select {
		case got := <-done:
			if got {
				t.Fatal("disconnect confirmed")
			}
		case <-time.After(time.Second):
			t.Fatal("disconnect hung")
		}
	})
}

func TestSessionPromptUsesInvocationContext(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		t.Run(map[bool]string{false: "pipe", true: "pty"}[terminal], func(t *testing.T) {
			r, w := io.Pipe()
			defer r.Close()
			defer w.Close()
			streams := terminalStreams(t.Context(), r, service.IO{Stderr: io.Discard, Terminal: service.Terminal{Present: terminal}})
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := streams.Prompt(ctx, "Remove? [y/N] ", 1024)
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("prompt ignored the invocation deadline")
			}
			if t.Context().Err() != nil {
				t.Fatal("prompt cancelled its owning session")
			}
			written := make(chan error, 1)
			go func() { _, err := io.WriteString(w, "next\n"); written <- err }()
			line, err := readLineLimit(streams.Input(t.Context()), 1024)
			if err != nil || line != "next" {
				t.Fatal("prompt consumed the next command", line, err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSessionPromptMissingStreams(t *testing.T) {
	for _, streams := range []service.IO{{Stderr: io.Discard}, {Stdin: strings.NewReader("yes\n")}} {
		if sessionPrompt(streams) != nil {
			t.Fatal("incomplete streams exposed a prompt")
		}
	}
}
