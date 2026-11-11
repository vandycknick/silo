package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/tsgate/internal/wire"
	"golang.org/x/sys/unix"
	"tailscale.com/envknob"
)

func TestUsageAndSocketValidation(t *testing.T) {
	for _, args := range [][]string{nil, {"--other"}, {"--control-fd", "bad"}, {"--control-fd", "-1"}, {"--control-fd", "999999"}, {"version", "extra"}} {
		var stderr bytes.Buffer
		if code := run(args, &stderr); code != 2 || stderr.Len() == 0 {
			t.Fatal(args, code, stderr.String())
		}
	}
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if code := run([]string{"--control-fd", strconv.Itoa(int(file.Fd()))}, io.Discard); code != 2 {
		t.Fatal(code)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	tcpFile, err := listener.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer tcpFile.Close()
	if code := run([]string{"--control-fd", strconv.Itoa(int(tcpFile.Fd()))}, io.Discard); code != 2 {
		t.Fatal(code)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	if code := run([]string{"--control-fd", strconv.Itoa(fds[0])}, io.Discard); code != 2 {
		t.Fatal(code)
	}
}
func TestCommandUnixStream(t *testing.T) {
	a, b, err := wire.SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()
	f, err := b.File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fd, err := unix.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan int, 1)
	go func() { done <- run([]string{"--control-fd", strconv.Itoa(fd)}, io.Discard) }()
	w := &wire.Writer{Conn: a}
	if err = w.Send(wire.Bootstrap{Type: "bootstrap", Version: 1, Hostname: "lobby", Tag: "tag:lobby", StateDir: filepath.Join(t.TempDir(), "state"), ControlURL: "http://127.0.0.1:1"}, nil); err != nil {
		t.Fatal(err)
	}
	a.Close()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatal(code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("command survived owner loss")
	}
}
func TestBootEnvironmentBeforeUpstreamInit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBootEnvironmentChild$")
	cmd.Env = append(os.Environ(), "TSGATE_TEST_CHILD=1", "GODEBUG=inittrace=1", "TS_DEBUG_DISABLE_PORTMAPPER=true", "TS_AUTHKEY=secret", "TSNET_FORCE_LOGIN=1", "SILO_NET_SECRET=secret")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, output)
	}
	trace := string(output)
	guard := strings.Index(trace, "init github.com/vandycknick/silo/app/tsgate/internal/bootenv @")
	upstream := strings.Index(trace, "init tailscale.com/envknob @")
	magicsock := strings.Index(trace, "init tailscale.com/wgengine/magicsock @")
	if guard < 0 || upstream < guard || magicsock < guard {
		t.Fatalf("environment isolation initialized too late:\n%s", trace)
	}
}
func TestBootEnvironmentChild(t *testing.T) {
	if os.Getenv("TSGATE_TEST_CHILD") != "1" {
		t.Skip("subprocess only")
	}
	for _, name := range []string{"TS_DEBUG_DISABLE_PORTMAPPER", "TS_AUTHKEY", "TSNET_FORCE_LOGIN", "SILO_NET_SECRET"} {
		if _, set := os.LookupEnv(name); set {
			t.Fatal("ambient setting survived", name)
		}
	}
	if envknob.Bool("TS_DEBUG_DISABLE_PORTMAPPER") {
		t.Fatal("upstream cached ambient setting")
	}
}
