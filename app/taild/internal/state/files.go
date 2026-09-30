package state

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/vandycknick/silo/app/taild/internal/identity"
)

func PrivateDir(path string) error {
	if e := os.MkdirAll(path, 0700); e != nil {
		return e
	}
	info, e := os.Lstat(path)
	if e != nil {
		return e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || int(st.Uid) != os.Geteuid() || info.Mode().Perm()&0077 != 0 {
		return errors.New("state directory must be owned and private")
	}
	return nil
}
func AtomicWrite(path string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".taild-")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	return SyncDir(filepath.Dir(path))
}
func SyncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func PrincipalDir(home string, p identity.Principal) (string, error) {
	if _, e := identity.ParsePrincipal(string(p)); e != nil {
		return "", e
	}
	path := filepath.Join(home, "taild", "principals", base64.RawURLEncoding.EncodeToString([]byte(p)))
	if e := PrivateDir(path); e != nil {
		return "", e
	}
	return path, nil
}
func Instance(home string) (string, error) {
	path := filepath.Join(home, "taild", "instance")
	b, e := os.ReadFile(path)
	if e == nil {
		s := strings.TrimSpace(string(b))
		decoded, err := hex.DecodeString(s)
		if err != nil || len(decoded) != 16 {
			return "", errors.New("invalid taild instance")
		}
		return s, nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return "", e
	}
	b = make([]byte, 16)
	if _, e = rand.Read(b); e != nil {
		return "", e
	}
	s := hex.EncodeToString(b)
	return s, AtomicWrite(path, []byte(s+"\n"))
}
func PinTailnet(home, name string) error {
	if name == "" || strings.ContainsAny(name, "\n\r\x00") {
		return errors.New("missing verified tailnet")
	}
	path := filepath.Join(home, "taild", "tailnet")
	b, e := os.ReadFile(path)
	if e == nil {
		if strings.TrimSpace(string(b)) != name {
			return errors.New("tailnet differs from pinned identity")
		}
		return nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return AtomicWrite(path, []byte(name+"\n"))
}
