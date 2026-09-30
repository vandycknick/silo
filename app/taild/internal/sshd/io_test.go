package sshd

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestInputCancellationPreservesNextCommand(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	input := newInput(parent, reader)
	command, stop := context.WithCancel(parent)
	done := make(chan error, 1)
	go func() { var b [1]byte; _, e := input.Reader(command).Read(b[:]); done <- e }()
	stop()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("input did not detach")
	}
	go func() { _, e := io.WriteString(writer, "whoami\n"); done <- e }()
	line, e := readLine(input.Reader(parent))
	if e != nil || line != "whoami" {
		t.Fatal(line, e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

func TestSharedInputCRLFAndGuestData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	input := newInput(ctx, strings.NewReader("rm vm\r\nyes\r\nshow vm\r\nexec vm -- cat\r\nhello\n\x00data"))
	for _, want := range []string{"rm vm", "yes", "show vm", "exec vm -- cat"} {
		// Distinct command-scoped readers still share the delimiter state.
		got, e := readLineLimit(input.Reader(ctx), 1024)
		if e != nil || got != want {
			t.Fatalf("want %q got %q: %v", want, got, e)
		}
	}
	data, e := io.ReadAll(input.Reader(ctx))
	if e != nil || string(data) != "hello\n\x00data" {
		t.Fatalf("guest input %q: %v", data, e)
	}
}

func TestSharedInputCROnlyDoesNotWaitForLookahead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	input := newInput(ctx, reader)
	done := make(chan error, 1)
	go func() { _, e := io.WriteString(writer, "whoami\r"); done <- e }()
	line, e := readLine(input.Reader(ctx))
	if e != nil || line != "whoami" {
		t.Fatal("CR-only command waited for more input", line, e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	// CRLF may arrive in a later chunk. Consume that LF, but keep the first
	// actual guest byte, and do not apply CR normalization to subsequent data.
	go func() {
		_, e := io.WriteString(writer, "\nhello\r\n")
		if e == nil {
			e = writer.Close()
		}
		done <- e
	}()
	data, e := io.ReadAll(input.Reader(ctx))
	if e != nil || string(data) != "hello\r\n" {
		t.Fatal(string(data), e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

func TestSharedInputCROnlyPreservesNonLFNextByte(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	input := newInput(ctx, strings.NewReader("shell vm\rhello"))
	if line, e := readLine(input.Reader(ctx)); e != nil || line != "shell vm" {
		t.Fatal(line, e)
	}
	data, e := io.ReadAll(input.Reader(ctx))
	if e != nil || string(data) != "hello" {
		t.Fatal(string(data), e)
	}
}
func TestBackpressuredOutputClosesOnStreamCancellation(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	output := sessionOutput{context.Background(), writer, func() { _ = reader.Close() }}
	done := make(chan error, 1)
	go func() { _, e := output.WriteContext(ctx, []byte("real pipe output")); done <- e }()
	var first [1]byte
	if _, e := reader.Read(first[:]); e != nil {
		t.Fatal(e)
	}
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancelled write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("backpressured output ignored cancellation")
	}
}
