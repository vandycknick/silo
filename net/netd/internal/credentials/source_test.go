package credentials

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func loadPipe(t *testing.T, frame string) (*Static, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	fd, err := unix.Dup(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := w.WriteString(frame); _ = w.Close(); done <- err }()
	source, err := loadFromFD(fd, time.Second)
	if writeErr := <-done; writeErr != nil && err == nil {
		t.Fatal(writeErr)
	}
	if _, closeErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); closeErr == nil {
		t.Fatal("secrets descriptor left open")
	}
	return source, err
}
func framed(body string) string { return fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body) }

func TestLoadFromFDValidBinaryReservedAndDefaults(t *testing.T) {
	body := `{"version":1,"secrets":[{"name":"silo.ssh_ca.private_key","value":"AP8="}],"provider":{"version":1,"command":"/bin/helper","args":[],"grant":"AP8="}}`
	source, err := loadPipe(t, framed(body))
	if err != nil {
		t.Fatal(err)
	}
	v, ok := source.Lookup("silo.ssh_ca.private_key")
	if !ok || !bytes.Equal(v, []byte{0, 255}) {
		t.Fatal("binary reserved value lost")
	}
	v[0] = 1
	v, _ = source.Lookup("silo.ssh_ca.private_key")
	if v[0] != 0 {
		t.Fatal("Lookup exposed mutable storage")
	}
	if !bytes.Equal(source.provider.Grant, []byte{0, 255}) || source.refreshSkew() != 300*time.Second {
		t.Fatal("provider grant/default mismatch")
	}
	empty, err := loadPipe(t, framed(`{"version":1,"secrets":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := empty.Refresh(context.Background(), nil, "expired"); err != ErrNoProvider {
		t.Fatal(err)
	}
}

func TestLoadFromFDRejectsMalformed(t *testing.T) {
	provider := func(fields string) string { return `{"version":1,"secrets":[],"provider":{` + fields + `}}` }
	base := `"version":1,"command":"/bin/helper","args":[],"grant":"eA=="`
	bodies := []string{
		"", `{`, `{}`, `[]`, `null`, `{"version":2,"secrets":[]}`, `{"secrets":[]}`, `{"version":1}`, `{"version":1,"secrets":null}`,
		`{"version":1,"secrets":[],"extra":1}`, `{"version":1,"version":1,"secrets":[]}`,
		`{"Version":1,"secrets":[]}`, `{"version":1,"secrets":[{"Name":"x","value":"eA=="}]}`,
		`{"version":1,"secrets":[{"name":"x","value":"eA==","extra":0}]}`,
		`{"version":1,"secrets":[{"name":"x","value":"eA=="},{"name":"x","value":"eQ=="}]}`,
		`{"version":1,"secrets":[{"name":"x"}]}`, `{"version":1,"secrets":[{"value":"eA=="}]}`,
		`{"version":1,"secrets":[{"name":".bad","value":"eA=="}]}`, `{"version":1,"secrets":[{"name":"x","value":"eA"}]}`,
		`{"version":1,"secrets":[{"name":"x","value":"eB=="}]}`, `{"version":1,"secrets":[{"name":"x","value":"eA==\n"}]}`,
		`{"version":1,"secrets":[]} {}`, provider(`"command":"/bin/helper","args":[],"grant":"eA=="`),
		provider(`"version":2,"command":"/bin/helper","args":[],"grant":"eA=="`), provider(`"version":1,"command":"relative","args":[],"grant":"eA=="`),
		provider(`"version":1,"command":"/bin/helper","grant":"eA=="`), provider(`"version":1,"command":"/bin/helper","args":[],"grant":"bad"`),
		provider(`"version":1,"command":"/bin/helper","args":[]`), provider(base + `,"unknown":1`),
		provider(base + `,"timeout_ms":-1`), provider(base + `,"timeout_ms":1.5`), provider(base + `,"timeout_ms":9223372036854775807`),
		provider(base + `,"refresh_skew_seconds":-1`), provider(base + `,"refresh_skew_seconds":9223372036854775807`), provider(base + `,"timeout_ms":null`),
	}
	for i, body := range bodies {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if _, err := loadPipe(t, framed(body)); err == nil {
				t.Fatal("accepted invalid JSON")
			}
		})
	}
	for i, frame := range []string{
		"", "Content-Length: 20\r\n\r\n{}", "Content-Length: 16385\r\n\r\n", "Content-Length: -1\r\n\r\n", "Content-Length: +2\r\n\r\n{}",
		"Content-Length: 2\n\n{}", strings.Repeat("x", 129), "Content-Length: 2\r\nX: x\r\n\r\n{}", framed(`{"version":1,"secrets":[]}`) + " ", framed(`{"version":1,"secrets":[]}`) + framed(`{}`),
	} {
		t.Run("frame"+fmt.Sprint(i), func(t *testing.T) {
			if _, err := loadPipe(t, frame); err == nil {
				t.Fatal("accepted invalid frame")
			}
		})
	}
}

func TestLoadFromFDMaximumBody(t *testing.T) {
	body := `{"version":1,"secrets":[]}`
	body += strings.Repeat(" ", MaxSecretsBody-len(body))
	if _, err := loadPipe(t, framed(body)); err != nil {
		t.Fatal(err)
	}
}

func TestLoadFromFDTimeoutRequiresEOF(t *testing.T) {
	for _, body := range []string{"", framed(`{"version":1,"secrets":[]}`), "Content-Length: 100\r\n\r\n{"} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Dup(int(r.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.WriteString(body); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		_, err = loadFromFD(fd, 30*time.Millisecond)
		_ = r.Close()
		_ = w.Close()
		if err == nil || time.Since(start) > time.Second {
			t.Fatalf("unbounded or accepted open pipe: %v", err)
		}
	}
}

func TestLoadFromFDRejectsDescriptorKinds(t *testing.T) {
	for _, fd := range []int{-2, -1, 0, 1, 2} {
		if _, err := LoadFromFD(fd); err == nil {
			t.Fatal("accepted low descriptor")
		}
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	file, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for _, f := range []*os.File{w, file} {
		fd, err := unix.Dup(int(f.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFromFD(fd); err == nil {
			t.Fatal("accepted non-reader FIFO")
		}
	}
}

func TestLoadFromFDMarksCLOEXECWhileWaiting(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	fd, err := unix.Dup(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := loadFromFD(fd, time.Second); result <- err }()
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil {
			t.Fatal(err)
		}
		if flags&unix.FD_CLOEXEC != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("secrets descriptor not marked CLOEXEC")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := w.WriteString(framed(`{"version":1,"secrets":[]}`)); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestStaticCopiesInputsAndConcurrentLookups(t *testing.T) {
	values := map[string][]byte{"x": []byte("before")}
	source := NewStatic(values, nil)
	values["x"][0] = 'X'
	done := make(chan struct{}, 8)
	for range 8 {
		go func() {
			defer func() { done <- struct{}{} }()
			for range 100 {
				value, _ := source.Lookup("x")
				if string(value) != "before" {
					t.Error("storage alias")
				}
			}
		}()
	}
	for range 8 {
		<-done
	}
}
