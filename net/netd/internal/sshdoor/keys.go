package sshdoor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func parseCA(data []byte) (ssh.Signer, error) {
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("machine SSH CA must contain exactly one unencrypted private key")
	}
	raw, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse unencrypted machine SSH CA: %w", err)
	}
	if _, ok := raw.(*ed25519.PrivateKey); !ok {
		return nil, errors.New("machine SSH CA must be Ed25519")
	}
	return ssh.NewSignerFromKey(raw)
}

func issue(ca ssh.Signer, user string, id Identity, request string, now time.Time) (ssh.Signer, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	cert := &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.UserCert, KeyId: "silo:tailnet:" + id.Login + ":" + request,
		ValidPrincipals: []string{user}, ValidAfter: uint64(now.Add(-time.Minute).Unix()), ValidBefore: uint64(now.Add(5 * time.Minute).Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{"permit-pty": "", "permit-agent-forwarding": "", "permit-port-forwarding": ""}}}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		return nil, err
	}
	return ssh.NewCertSigner(cert, signer)
}

// All accesses are descriptor-relative, owner-only and reject symlinks. The
// known_host.lock flock is the same lock used by common/utils/src/ssh.rs.
func openSSHDir(dir string) (*os.File, error) {
	parentFD, err := unix.Open(filepath.Dir(dir), unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parent := os.NewFile(uintptr(parentFD), filepath.Dir(dir))
	defer parent.Close()
	if err := unix.Mkdirat(parentFD, filepath.Base(dir), 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(dir), unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), dir)
	var st, pst unix.Stat_t
	if err = unix.Fstat(fd, &st); err == nil {
		err = unix.Fstat(int(parent.Fd()), &pst)
	}
	if err != nil || st.Uid != uint32(os.Geteuid()) || st.Uid != pst.Uid || st.Mode&0777 != 0700 {
		f.Close()
		return nil, errors.New("SSH directory must be owner-owned mode 0700 with the same owner as its parent")
	}
	return f, nil
}

func openPrivate(dir *os.File, name string, flags int) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 {
		f.Close()
		return nil, errors.New("SSH file must be an owner-owned regular file mode 0600")
	}
	return f, nil
}

func lock(ctx context.Context, dir *os.File, name string) (*os.File, error) {
	f, err := openPrivate(dir, name, unix.O_RDWR|unix.O_CREAT)
	if err != nil {
		return nil, err
	}
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func hostKey(ctx context.Context, dir *os.File) (ssh.Signer, error) {
	l, err := lock(ctx, dir, "tailnet_host_ed25519_key.lock")
	if err != nil {
		return nil, err
	}
	defer l.Close()
	const name = "tailnet_host_ed25519_key"
	f, err := openPrivate(dir, name, unix.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		_, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return nil, e
		}
		block, e := ssh.MarshalPrivateKey(key, "silo tailnet host")
		if e != nil {
			return nil, e
		}
		temp := fmt.Sprintf(".%s.%d.%d", name, os.Getpid(), time.Now().UnixNano())
		out, e := openPrivate(dir, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
		if e != nil {
			return nil, e
		}
		defer unix.Unlinkat(int(dir.Fd()), temp, 0)
		_, e = out.Write(pem.EncodeToMemory(block))
		if e == nil {
			e = out.Sync()
		}
		e = errors.Join(e, out.Close())
		if e == nil {
			e = unix.Renameat(int(dir.Fd()), temp, int(dir.Fd()), name)
		}
		if e == nil {
			e = dir.Sync()
		}
		if e != nil {
			return nil, e
		}
		f, err = openPrivate(dir, name, unix.O_RDONLY)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := readBounded(f, 16384)
	if err != nil {
		return nil, err
	}
	return parseCA(data)
}

func guestPin(ctx context.Context, dir *os.File) (ssh.PublicKey, error) {
	l, err := lock(ctx, dir, "known_host.lock")
	if err != nil {
		return nil, err
	}
	defer l.Close()
	f, err := openPrivate(dir, "known_host", unix.O_RDONLY)
	if err != nil {
		return nil, fmt.Errorf("existing libvm guest host pin required: %w", err)
	}
	defer f.Close()
	data, err := readBounded(f, 16384)
	if err != nil {
		return nil, err
	}
	key, _, _, rest, err := ssh.ParseAuthorizedKey(data)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("invalid guest host pin")
	}
	return key, nil
}
