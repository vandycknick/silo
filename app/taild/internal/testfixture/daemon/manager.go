package daemon

import (
	"context"
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

func launchManager(t *testing.T, c config.Config) (*control.Client, config.Config) {
	t.Helper()
	bin := testfixture.Path(t, "SILO_TEST_BIN_DIR", true)
	runRoot := testfixture.ShortTempDir(t)
	t.Setenv("SILO_RUN_ROOT", runRoot)
	home, err := filepath.EvalSymlinks(c.Home)
	if err != nil {
		t.Fatal(err)
	}
	configRoot := t.TempDir()
	configDir := filepath.Join(configRoot, "silo")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	configDir, err = filepath.EvalSymlinks(configDir)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(filepath.Join(bin, "silod"), "--system-enabled=false", "--tailscale-enabled=false")
	command.Env = []string{"HOME=" + home, "SILO_HOME=" + home, "XDG_CONFIG_HOME=" + configRoot, "PATH=" + os.Getenv("PATH"), "SILO_RUNTIME_DIR=" + filepath.Dir(c.Components.AssetDir), "SILO_RUN_ROOT=" + runRoot}
	for _, key := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if value := os.Getenv(key); value != "" {
			command.Env = append(command.Env, key+"="+value)
		}
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	stop := func() {
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
	endpoint := filepath.Join(runRoot, "silod", "control.sock")
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
