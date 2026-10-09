package sshdoor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestRealOpenSSHTransferClients(t *testing.T) {
	f := localFixture(t)
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("SKIPPED: ssh client absent")
	}
	known := filepath.Join(f.dir, "client-known-hosts")
	host, port, err := splitAddress(f.address)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(known, append([]byte("["+host+"]:"+port+" "), ssh.MarshalAuthorizedKey(f.door.host.PublicKey())...), 0600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(f.dir, "client-config")
	text := fmt.Sprintf("Host relay\n HostName %s\n Port %s\n User %s\n UserKnownHostsFile %s\n StrictHostKeyChecking yes\n BatchMode yes\n ConnectTimeout 5\n", host, port, f.user, known)
	if err := os.WriteFile(config, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 2<<20)
	if os.Getenv("SILO_TEST_SSH_200MB") == "1" {
		data = make([]byte, 200_000_000)
	}
	for i := range data {
		data[i] = byte(i * 17)
	}
	source := filepath.Join(f.dir, "source.bin")
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	run := func(t *testing.T, bin string, args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(f.ctx, 60*time.Second)
		defer cancel()
		start := time.Now()
		out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v: %s", bin, err, out)
		}
		t.Logf("%s duration=%s bytes=%d", filepath.Base(bin), time.Since(start), len(data))
	}
	for _, name := range []string{"scp", "sftp", "rsync"} {
		t.Run(name, func(t *testing.T) {
			bin, err := exec.LookPath(name)
			if err != nil {
				t.Skipf("SKIPPED: %s binary absent", name)
			}
			dest := filepath.Join(f.dir, name+"-remote.bin")
			back := filepath.Join(f.dir, name+"-back.bin")
			switch name {
			case "scp":
				run(t, bin, "-F", config, source, "relay:"+dest)
				run(t, bin, "-F", config, "relay:"+dest, back)
			case "sftp":
				batch := filepath.Join(f.dir, "sftp-batch")
				os.WriteFile(batch, []byte("put "+source+" "+dest+"\nget "+dest+" "+back+"\n"), 0600)
				run(t, bin, "-F", config, "-b", batch, "relay")
			case "rsync":
				run(t, bin, "-e", sshBin+" -F "+config, source, "relay:"+dest)
				run(t, bin, "-e", sshBin+" -F "+config, "relay:"+dest, back)
			}
			got, err := os.ReadFile(back)
			if err != nil {
				t.Fatal(err)
			}
			if sha256.Sum256(data) != sha256.Sum256(got) {
				t.Fatal("transfer hash mismatch")
			}
		})
	}
	// Legacy scp is exec-based, unlike modern scp's SFTP default.
	t.Run("legacy-scp", func(t *testing.T) {
		bin, err := exec.LookPath("scp")
		if err != nil {
			t.Skip("SKIPPED: scp absent")
		}
		dest := filepath.Join(f.dir, "legacy.bin")
		run(t, bin, "-O", "-F", config, source, "relay:"+dest)
		got, err := os.ReadFile(dest)
		if err != nil || !bytes.Equal(data, got) {
			t.Fatalf("legacy scp: %v", err)
		}
	})
}

func splitAddress(address string) (string, string, error) {
	// The fixture listener is always IPv4 loopback.
	var port int
	_, err := fmt.Sscanf(address, "127.0.0.1:%d", &port)
	if err != nil {
		return "", "", err
	}
	return "127.0.0.1", strconv.Itoa(port), nil
}

func TestGuestPinMismatchFailsClosed(t *testing.T) {
	f := localFixture(t)
	before, err := os.ReadFile(filepath.Join(f.dir, "ssh/known_host"))
	if err != nil {
		t.Fatal(err)
	}
	other, _ := testKey(t)
	wrong := ssh.MarshalAuthorizedKey(other.PublicKey())
	if err := os.WriteFile(filepath.Join(f.dir, "ssh/known_host"), wrong, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	if c, _, _, raw, err := f.door.connect(ctx, f.user, Identity{Login: "offline"}, "mismatch"); err == nil {
		c.Close()
		raw.Close()
		t.Fatal("wrong pin accepted")
	}
	after, err := os.ReadFile(filepath.Join(f.dir, "ssh/known_host"))
	if err != nil || !bytes.Equal(wrong, after) {
		t.Fatal("mismatched pin overwritten")
	}
	if err := os.WriteFile(filepath.Join(f.dir, "ssh/known_host"), before, 0600); err != nil {
		t.Fatal(err)
	}
}
