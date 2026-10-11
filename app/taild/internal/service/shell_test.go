package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

type dataEOFReader struct{ done bool }

func (r *dataEOFReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	return copy(p, "last"), io.EOF
}

type failingShellReader struct{}

func (failingShellReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestShellEOFDataAndEOTOrdering(t *testing.T) {
	reader := eofAdapter(context.Background(), &dataEOFReader{})
	var got bytes.Buffer
	p := make([]byte, 1)
	// Exercise tiny EOT reads separately; the data-bearing read needs room.
	first := make([]byte, 16)
	n, err := reader.Read(first)
	if err != nil || string(first[:n]) != "last" {
		t.Fatal(n, err, string(first[:n]))
	}
	got.Write(first[:n])
	for {
		n, err := reader.Read(p)
		got.Write(p[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got.Bytes(), []byte{'l', 'a', 's', 't', 4, 4}) {
		t.Fatalf("%q", got.Bytes())
	}
	n, err = reader.Read(p)
	if n != 0 || err != io.EOF {
		t.Fatal(n, err)
	}
}

func TestShellEOFCancellationAndReadFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := make([]byte, 8)
	n, err := eofAdapter(ctx, strings.NewReader("")).Read(p)
	if n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal(n, err)
	}
	n, err = eofAdapter(context.Background(), failingShellReader{}).Read(p)
	if n != 0 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(n, err)
	}
}

type plainShellWriter struct{}

func (plainShellWriter) Write(p []byte) (int, error) { return len(p), nil }
func TestShellRejectsUnknownBlockingWriter(t *testing.T) {
	if _, err := shellWriter(plainShellWriter{}); err == nil {
		t.Fatal("plain potentially blocking writer accepted")
	}
	var output bytes.Buffer
	writer, err := shellWriter(&output)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if n, err := writer.WriteContext(ctx, []byte("no")); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal(n, err)
	}
	if output.Len() != 0 {
		t.Fatal(output.String())
	}
}
