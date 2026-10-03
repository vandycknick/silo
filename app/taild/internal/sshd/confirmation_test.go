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
				if got := confirmRemoval(ctx, streams, service.RemovalTarget{Name: "devbox"}); got != tc.want {
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
		if confirmRemoval(context.Background(), service.IO{Stderr: &out}, service.RemovalTarget{Name: "devbox"}) || out.Len() != 0 {
			t.Fatal("nil input did not cancel")
		}
	})
	t.Run("running", func(t *testing.T) {
		var out bytes.Buffer
		if confirmRemoval(context.Background(), service.IO{Stdin: strings.NewReader("no\n"), Stderr: &out}, service.RemovalTarget{Name: "devbox", Running: true}) || out.String() != "Stop and remove VM 'devbox'? [y/N] " {
			t.Fatal(out.String())
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
		go func() { done <- confirmRemoval(ctx, streams, service.RemovalTarget{Name: "devbox"}) }()
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
