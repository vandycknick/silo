package daemon

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/control"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	silo "github.com/vandycknick/silo/sdk/go"
	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/emptypb"
)

// launchManager excludes every fixture sharing the fixed per-UID endpoint.
// The lock is held until the child has been reaped, not just until readiness.
func launchManager(t *testing.T, c config.Config) (*control.Client, config.Config) {
	t.Helper()
	bin := testfixture.Path(t, "SILO_TEST_BIN_DIR", true)
	lock, err := os.OpenFile(fmt.Sprintf("/tmp/silo-control-fixture-%d.lock", os.Getuid()), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		t.Fatal("use an idle dedicated test UID and serialized packages:", err)
	}
	release := func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN); _ = lock.Close() }
	if err := exec.Command("pgrep", "-u", fmt.Sprint(os.Getuid()), "-x", "silod").Run(); err == nil {
		release()
		t.Fatal("live silod found; fixture never adopts an existing daemon")
	}
	home, err := filepath.EvalSymlinks(c.Home)
	if err != nil {
		release()
		t.Fatal(err)
	}
	configRoot := t.TempDir()
	configDir := filepath.Join(configRoot, "silo")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		release()
		t.Fatal(err)
	}
	configDir, err = filepath.EvalSymlinks(configDir)
	if err != nil {
		release()
		t.Fatal(err)
	}
	command := exec.Command(filepath.Join(bin, "silod"), "--system-enabled=false", "--tailscale-enabled=false")
	command.Env = []string{"HOME=" + home, "SILO_HOME=" + home, "XDG_CONFIG_HOME=" + configRoot, "PATH=" + os.Getenv("PATH"), "SILO_RUNTIME_DIR=" + filepath.Dir(c.Components.AssetDir)}
	for _, key := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if value := os.Getenv(key); value != "" {
			command.Env = append(command.Env, key+"="+value)
		}
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		release()
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	stop := func() {
		defer release()
		_ = command.Process.Signal(unix.SIGTERM)
		select {
		case err := <-exited:
			if err != nil {
				t.Error("silod exit:", err)
			}
		case <-time.After(90 * time.Second):
			_ = command.Process.Kill()
			<-exited
			t.Error("silod failed to drain")
		}
	}
	// Register now so any failure during admission still reaps the daemon.
	t.Cleanup(stop)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	endpoint := fmt.Sprintf("/tmp/silo-%d/silod/control.sock", os.Getuid())
	var client *control.Client
	var status *w.DaemonStatus
	for {
		client, err = control.New(endpoint, "")
		if err == nil {
			probe, done := context.WithTimeout(ctx, time.Second)
			status, err = client.Daemon.GetStatus(probe, &emptypb.Empty{})
			done()
			if err == nil && status.Core == w.CorePhase_CORE_PHASE_READY {
				break
			}
			_ = client.Close()
		}
		select {
		case <-ctx.Done():
			t.Fatal("silod readiness:", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Cleanup(func() { _ = client.Close() })
	if status.Schema != 2 || status.Pid != uint32(command.Process.Pid) || status.ProcessStart == "" || status.Generation == "" || string(status.ControlEndpoint) != endpoint || status.System != nil || status.Tailscale.GetEnabled() {
		t.Fatal("fixture daemon process/component identity mismatch")
	}
	if _, err := client.Admit(ctx, silo.Version, status.Generation, home, configDir); err != nil {
		t.Fatal(err)
	}
	info, err := client.Daemon.GetRuntimeInfo(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if info.Generation != status.Generation || string(info.Home) != home || info.Components == nil {
		t.Fatal("fixture runtime identity mismatch")
	}
	c.Home = home
	r := info.Components
	for _, asset := range []struct {
		source []byte
		target *string
	}{
		{r.SupervisorPath, &c.Components.SupervisorPath}, {r.NetdPath, &c.Components.NetdPath},
		{r.KernelPath, &c.Components.KernelPath}, {r.InitramfsPath, &c.Components.InitramfsPath},
		{r.AgentPath, &c.Components.AgentPath}, {r.AssetDir, &c.Components.AssetDir},
	} {
		if !utf8.Valid(asset.source) || !filepath.IsAbs(string(asset.source)) {
			t.Fatal("invalid runtime component path")
		}
		*asset.target = string(asset.source)
	}
	return client, c
}
