package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"golang.org/x/sys/unix"
)

var errOperatorReadOnly = failure("forbidden", "operator documents are read-only", 4)

// All paths are walked through directory descriptors with NOFOLLOW, including
// ancestors. Anchored operations cannot follow a swapped directory or file link.
func documentDir(path string, privateFrom string, create bool) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("absolute document directory required")
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	current := os.NewFile(uintptr(fd), "/")
	walked := ""
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/") {
		walked += "/" + part
		private := privateFrom != "" && (walked == privateFrom || strings.HasPrefix(walked, privateFrom+"/"))
		next, e := unix.Openat(int(current.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(e, unix.ENOENT) && create && private {
			if e = unix.Mkdirat(int(current.Fd()), part, 0700); e == nil || errors.Is(e, unix.EEXIST) {
				next, e = unix.Openat(int(current.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			}
		}
		_ = current.Close()
		if e != nil {
			return nil, e
		}
		current = os.NewFile(uintptr(next), walked)
		if private {
			info, e := current.Stat()
			if e != nil {
				_ = current.Close()
				return nil, e
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || int(st.Uid) != os.Geteuid() || info.Mode().Perm()&0077 != 0 {
				_ = current.Close()
				return nil, errors.New("document directory must be owned and private")
			}
		}
	}
	return current, nil
}
func readDocument(dir *os.File, name string, private bool) (string, error) {
	fd, e := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return "", e
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return "", e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Size() > DocumentLimit || private && (!ok || int(st.Uid) != os.Geteuid() || info.Mode().Perm()&0077 != 0) {
		return "", errors.New("invalid document file")
	}
	b, e := io.ReadAll(io.LimitReader(f, DocumentLimit+1))
	if e != nil {
		return "", e
	}
	if len(b) > DocumentLimit {
		return "", errors.New("document exceeds 64KiB")
	}
	return string(b), nil
}
func writeDocument(dir *os.File, name, raw string, create bool) error {
	var entropy [16]byte
	if _, e := rand.Read(entropy[:]); e != nil {
		return e
	}
	tmp := ".taild-" + hex.EncodeToString(entropy[:])
	fd, e := unix.Openat(int(dir.Fd()), tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Unlinkat(int(dir.Fd()), tmp, 0) }()
	f := os.NewFile(uintptr(fd), tmp)
	_, e = f.WriteString(raw)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if create {
		e = unix.Linkat(int(dir.Fd()), tmp, int(dir.Fd()), name, 0)
	} else {
		e = unix.Renameat(int(dir.Fd()), tmp, int(dir.Fd()), name)
	}
	if e != nil {
		return e
	}
	return dir.Sync()
}
func (s *Service) documentPaths(kind string, owner identity.Principal) (string, string, string) {
	ext := ".yaml"
	operator := s.Config.TemplatesDir
	if kind == "policy" {
		ext = ".hcl"
		operator = s.Config.PoliciesDir
	}
	return filepath.Join(s.Config.Home, "taild", "principals", base64.RawURLEncoding.EncodeToString([]byte(owner)), kind+"s"), operator, ext
}
func storeFailure(e error) error {
	if errors.Is(e, os.ErrNotExist) || errors.Is(e, unix.ENOENT) {
		return failure("not_found", "document not found", 3)
	}
	if errors.Is(e, unix.EEXIST) {
		return failure("conflict", "document already exists", 5)
	}
	return failure("unavailable", "document store unavailable or unsafe", 9)
}

// documentNames lists the stored documents with one extension, refusing
// oversized directories and names the store would never have written.
func documentNames(dir *os.File, ext string) ([]string, error) {
	entries, e := dir.ReadDir(4097)
	if e != nil && e != io.EOF {
		return nil, e
	}
	if len(entries) > 4096 {
		return nil, errors.New("document directory exceeds 4096 entries")
	}
	var names []string
	for _, f := range entries {
		if n, ok := strings.CutSuffix(f.Name(), ext); ok {
			if !config.ValidName(n) {
				return nil, errors.New("invalid stored document name")
			}
			names = append(names, n)
		}
	}
	return names, nil
}
func (s *Service) documentsFor(ctx context.Context, kind, verb, name string, owner identity.Principal, raw string) ([]Document, error) {
	s.documentMu.Lock()
	defer s.documentMu.Unlock()
	if _, e := identity.ParsePrincipal(string(owner)); e != nil {
		return nil, usageDocument()
	}
	if verb != "ls" && !config.ValidName(name) {
		return nil, errDocumentName
	}
	own, operator, ext := s.documentPaths(kind, owner)
	write := verb == "create" || verb == "edit" || verb == "rm"
	dir, e := documentDir(own, filepath.Join(s.Config.Home, "taild"), write)
	if e != nil && !errors.Is(e, unix.ENOENT) {
		return nil, storeFailure(e)
	}
	if dir != nil {
		defer dir.Close()
	}
	var op *os.File
	if operator != "" {
		op, e = documentDir(operator, "", false)
		if e != nil && !errors.Is(e, unix.ENOENT) {
			return nil, storeFailure(e)
		}
		if op != nil {
			defer op.Close()
		}
	}
	load := func(dir *os.File, n, tier string) (Document, error) {
		if dir == nil {
			return Document{}, unix.ENOENT
		}
		b, e := readDocument(dir, n+ext, tier == "yours")
		if e != nil {
			return Document{}, e
		}
		d, e := s.validateDocument(ctx, kind, b)
		if e != nil {
			return Document{}, failure("unavailable", "stored "+kind+" failed validation", 9)
		}
		d.Name = n
		d.Tier = tier
		if tier == "yours" {
			d.Owner = owner
		}
		return d, nil
	}
	if verb == "ls" {
		out := []Document{}
		for _, entry := range []struct {
			dir  *os.File
			tier string
		}{{dir, "yours"}, {op, "operator"}} {
			if entry.dir == nil {
				continue
			}
			names, e := documentNames(entry.dir, ext)
			if e != nil {
				return nil, storeFailure(e)
			}
			for _, n := range names {
				d, e := load(entry.dir, n, entry.tier)
				if e != nil {
					return nil, storeFailure(e)
				}
				d.Content = ""
				out = append(out, d)
			}
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Name == out[j].Name {
				return out[i].Tier > out[j].Tier
			}
			return out[i].Name < out[j].Name
		})
		return out, nil
	}
	existing, existingErr := load(dir, name, "yours")
	if existingErr != nil && !errors.Is(existingErr, unix.ENOENT) {
		return nil, storeFailure(existingErr)
	}
	switch verb {
	case "show":
		if existingErr == nil {
			return []Document{existing}, nil
		}
		d, e := load(op, name, "operator")
		if e != nil {
			return nil, storeFailure(e)
		}
		return []Document{d}, nil
	case "create", "edit":
		if verb == "create" && existingErr == nil {
			return nil, failure("conflict", "document already exists", 5)
		}
		if verb == "edit" && existingErr != nil {
			if _, e := load(op, name, "operator"); e == nil {
				return nil, errOperatorReadOnly
			}
			return nil, storeFailure(existingErr)
		}
		d, e := s.validateDocument(ctx, kind, raw)
		if e != nil {
			return nil, e
		}
		if e = writeDocument(dir, name+ext, d.Content, verb == "create"); e != nil {
			return nil, storeFailure(e)
		}
		d.Name = name
		d.Tier = "yours"
		d.Owner = owner
		return []Document{d}, nil
	case "rm":
		if existingErr != nil {
			if _, e := load(op, name, "operator"); e == nil {
				return nil, errOperatorReadOnly
			}
			return nil, storeFailure(existingErr)
		}
		if e := unix.Unlinkat(int(dir.Fd()), name+ext, 0); e != nil {
			return nil, storeFailure(e)
		}
		if e := dir.Sync(); e != nil {
			return nil, storeFailure(e)
		}
		return []Document{{Kind: kind, Name: name, Tier: "yours", Owner: owner}}, nil
	default:
		return nil, usageDocument()
	}
}

// Operator files are deliberately uncached. SIGHUP eagerly validates the same
// fresh view that every list/resolve reads, without replacing running VM policy.
func (s *Service) ReloadDocuments(ctx context.Context) error {
	s.documentMu.Lock()
	defer s.documentMu.Unlock()
	for _, kind := range []string{"template", "policy"} {
		_, path, ext := s.documentPaths(kind, "")
		if path == "" {
			continue
		}
		dir, e := documentDir(path, "", false)
		if errors.Is(e, unix.ENOENT) {
			continue
		}
		if e != nil {
			return storeFailure(e)
		}
		e = func() error {
			defer dir.Close()
			names, e := documentNames(dir, ext)
			if e != nil {
				return e
			}
			for _, n := range names {
				raw, e := readDocument(dir, n+ext, false)
				if e != nil {
					return e
				}
				if _, e = s.validateDocument(ctx, kind, raw); e != nil {
					return e
				}
			}
			return nil
		}()
		if e != nil {
			return storeFailure(e)
		}
	}
	return nil
}
