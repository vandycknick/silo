package credentials

import (
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLoadFromFDSmallPipeIncrementalDelivery(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if _, err := unix.FcntlInt(r.Fd(), unix.F_SETPIPE_SZ, 4096); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Dup(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := loadFromFD(fd, time.Second); result <- err }()
	body := `{"version":1,"secrets":[]}`
	body += strings.Repeat(" ", MaxSecretsBody-len(body))
	frame := framed(body)
	if err := w.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for len(frame) > 0 {
		n := min(512, len(frame))
		if _, err := w.WriteString(frame[:n]); err != nil {
			t.Fatal(err)
		}
		frame = frame[n:]
		time.Sleep(time.Millisecond)
	}
	_ = w.Close()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
