package bootstrap

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	silo "github.com/vandycknick/silo/sdk/go"
	daemonv1 "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

func pipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	return r, w
}

func ownedFD(t *testing.T, file *os.File) int {
	t.Helper()
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

func TestRealPipeFrameRejectionBeforeNativeInitialization(t *testing.T) {
	t.Setenv("SILO_GO_FFI_PATH", "/missing/bridge")
	for _, test := range []struct {
		name  string
		frame []byte
	}{
		{"truncated-header", []byte{0, 0}},
		{"empty", []byte{0, 0, 0, 0}},
		{"oversized", []byte{0, 1, 0, 1}},
		{"truncated-body", []byte{0, 0, 0, 4, 1}},
		{"malformed-protobuf", []byte{0, 0, 0, 1, 255}},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, w := pipe(t)
			if _, err := w.Write(test.frame); err != nil {
				t.Fatal(err)
			}
			_ = w.Close()
			fd := ownedFD(t, r)
			if _, _, err := Read(context.Background(), fd); err == nil {
				t.Fatal(err)
			}
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != unix.EBADF {
				t.Fatal("rejected bootstrap retained descriptor", err)
			}
		})
	}
	for _, wire := range []*daemonv1.HelperBootstrap{{ProtocolMajor: 2, ProductVersion: silo.Version}, {ProtocolMajor: 1, ProductVersion: "wrong-product"}} {
		r, w := pipe(t)
		body, err := proto.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(body)))
		go func() { _, _ = w.Write(header[:2]); _, _ = w.Write(header[2:]); _, _ = w.Write(body) }()
		if _, _, err := Read(context.Background(), ownedFD(t, r)); err == nil {
			t.Fatal(err)
		}
	}
	if os.Getenv("SILO_GO_FFI_PATH") != "/missing/bridge" {
		t.Fatal("invalid bootstrap reached native selection")
	}
}

func TestRealPipeBootstrapDeadlineAndCancellation(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		r, _ := pipe(t)
		fd, err := unix.Dup(int(r.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.SetNonblock(fd, true); err != nil {
			t.Fatal(err)
		}
		// NewFile registers the nonblocking FIFO with the runtime poller, as Read does.
		reader := os.NewFile(uintptr(fd), "deadline-bootstrap")
		ctx, cancel := context.WithCancel(context.Background())
		if cancelEarly {
			cancel()
		}
		start := time.Now()
		_, err = readFrame(ctx, reader, 30*time.Millisecond)
		cancel()
		_ = reader.Close()
		if err == nil || time.Since(start) > time.Second {
			t.Fatal("unbounded bootstrap read", err)
		}
	}
}

func TestRequiredFIFOAndAccessMode(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "not-pipe")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	r, w := pipe(t)
	for _, fd := range []int{-1, ownedFD(t, file), ownedFD(t, w)} {
		if _, _, err := Read(context.Background(), fd); err == nil {
			t.Fatal("invalid descriptor accepted", fd)
		}
	}
	if flags, err := unix.FcntlInt(r.Fd(), unix.F_GETFL, 0); err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		t.Fatal("real read pipe mode", flags, err)
	}
}

func TestOwnerEOFCancelsImmediately(t *testing.T) {
	r, w := pipe(t)
	cancelled := make(chan struct{})
	stop := Watch(r, func() { close(cancelled) })
	defer stop()
	_ = w.Close()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("owner EOF did not cancel")
	}
}

func TestUnexpectedPostBootstrapBytesLoseOwner(t *testing.T) {
	r, w := pipe(t)
	lost := make(chan struct{})
	stop := Watch(r, func() { close(lost) })
	defer stop()
	_, _ = w.Write([]byte{1})
	select {
	case <-lost:
	case <-time.After(time.Second):
		t.Fatal("unexpected owner data accepted")
	}
}

func TestOptionalCredentialBoundsAndNoDebugExposure(t *testing.T) {
	for _, value := range [][]byte{nil, []byte("opaque-value"), []byte(strings.Repeat("x", 16<<10))} {
		if err := validateCredential(value); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range [][]byte{{}, []byte(" \n"), []byte{255}, []byte("bad\x00value"), []byte(strings.Repeat("x", (16<<10)+1))} {
		if err := validateCredential(value); err == nil {
			t.Fatal("invalid credential accepted")
		}
	}
	input := &Input{}
	input.Secrets.ClientSecret = "opaque-value"
	for _, value := range []any{input, input.Secrets} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, value), "opaque-value") {
				t.Fatal("bootstrap debug representation leaked credentials")
			}
		}
	}
}

func TestCanonicalRootsRejectAliasesAndWrongFileTypes(t *testing.T) {
	root := t.TempDir()
	if _, err := canonical([]byte(root), true); err != nil {
		t.Fatal(err)
	}
	link := root + "-link"
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(link) })
	for _, value := range []string{"", "relative", root + "/../" + strings.TrimPrefix(root, "/"), link, root + "/missing"} {
		if _, err := canonical([]byte(value), true); err == nil {
			t.Fatal("invalid canonical root accepted", value)
		}
	}
	if _, err := canonical([]byte(root), false); err == nil {
		t.Fatal("directory accepted as runtime file")
	}
}
