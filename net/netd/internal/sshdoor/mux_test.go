package sshdoor

import (
	"bufio"
	"context"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestMuxFramingAndCancellation(t *testing.T) {
	for _, response := range []string{"OK 12345\nSSH-2.0-buffered\r\n", "OK 0\n", "OK 01\n", "OK -1\n", "NO 22\n", "OK 1 trailing\n"} {
		t.Run(response, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "mux")
			l, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := l.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				r := bufio.NewReader(c)
				line, _ := r.ReadString('\n')
				if line != "CONNECT 22\n" {
					t.Errorf("%q", line)
				}
				io.WriteString(c, response)
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			c, err := DialMux(ctx, path)
			if response == "OK 12345\nSSH-2.0-buffered\r\n" {
				if err != nil {
					t.Fatal(err)
				}
				b, _ := io.ReadAll(c)
				c.Close()
				if string(b) != "SSH-2.0-buffered\r\n" {
					t.Fatalf("%q", b)
				}
			} else if err == nil {
				c.Close()
				t.Fatal("invalid ACK accepted")
			}
			<-done
		})
	}
	path := filepath.Join(t.TempDir(), "mux")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(io.Discard, c)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if c, err := DialMux(ctx, path); err == nil {
		c.Close()
		t.Fatal("stalled ACK succeeded")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("setup cancellation did not close mux")
	}
}
