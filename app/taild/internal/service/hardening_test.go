package service

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/enroll"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	silo "github.com/vandycknick/silo/sdk/go"
	"golang.org/x/sys/unix"
)

func TestConsentPrecedesNativeMaterialization(t *testing.T) {
	s := actualService(t)
	registry := testfixture.OCIRegistry(t, "")
	s.Config.VM.DefaultImage = registry.Reference
	s.Config.VM.AllowedRegistries = []string{strings.Split(registry.Reference, "/")[0] + "/fixture"}
	s.Config.Enrollment.Mode = "oauth-app"
	s.VMNodesEnabled = true
	r := enroll.NewRegistry()
	oauth, err := enroll.NewOAuth(r, "tskey-app-test-secret", "https://silo.fixture.test/oauth/callback")
	if err != nil {
		t.Fatal(err)
	}
	s.Enrollment = &enroll.Manager{Config: s.Config, Secrets: config.Secrets{AppSecret: "tskey-app-test-secret"}, Pin: state.NodePin{Tailnet: "fixture", Suffix: "fixture.test"}, Registry: r, OAuth: oauth, Metrics: s.Runtime.Metrics}
	c := domainCaller(t, s, "user:1")
	op, err := s.Create(context.Background(), c, CreateRequest{Name: "offline", Tailscale: true, NoStart: true})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	link := ""
	for link == "" {
		current, _, e := s.Jobs.Observe(c.Peer, op.ID)
		if e != nil {
			t.Fatal(e)
		}
		for _, line := range current.Progress {
			if u, ok := strings.CutPrefix(line, "approve: "); ok {
				link = u
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("consent not started")
		}
		time.Sleep(time.Millisecond)
	}
	u, err := url.Parse(link)
	if err != nil || u.Query().Get("state") == "" {
		t.Fatal(link, err)
	}
	entries, err := s.Runtime.SDK.Inventory(context.Background())
	if err != nil || len(entries) != 0 || registry.Requests.Load() != 0 {
		t.Fatal("creation ran before consent", entries, err, registry.Requests.Load())
	}
	s.Jobs.InterruptIf(func() bool { return true })
	finished := waitOperation(t, s, c, op)
	if finished.Error == nil {
		t.Fatal("cancelled consent succeeded")
	}
	entries, err = s.Runtime.SDK.Inventory(context.Background())
	if err != nil || len(entries) != 0 || registry.Requests.Load() != 0 {
		t.Fatal("cancelled consent created a VM", entries, err)
	}
	s.createMu.Lock()
	if len(s.pending) != 0 || len(s.diskPending) != 0 {
		t.Error("quota/disk reservations leaked")
	}
	s.createMu.Unlock()
}

func TestShutdownMarkerBlocksNativeMutationsAndRegistryAdmission(t *testing.T) {
	s := actualService(t)
	c := domainCaller(t, s, "user:1")
	s.Jobs.Admission = func() bool { return !state.ShutdownPending(s.Config.Home) }
	if err := state.MarkShutdown(s.Config.Home); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(context.Background(), c, CreateRequest{Name: "sealed", NoStart: true}); Categorize(err).Exit != 9 {
		t.Fatal(err)
	}
	if _, err := s.Jobs.Submit("start", "sealed", "user:1", func(context.Context, func(string)) error { t.Error("sealed job ran"); return nil }); Categorize(err).Exit != 9 {
		t.Fatal(err)
	}
	if err := state.ClearShutdown(s.Config.Home); err != nil {
		t.Fatal(err)
	}
	s.Jobs.InterruptIf(func() bool { return true })
	select {
	case <-s.Jobs.Drained():
	case <-time.After(time.Second):
		t.Fatal("paused jobs did not drain")
	}
	s.Jobs.Resume()
	op, err := s.Jobs.Submit("start", "safe", "user:1", func(context.Context, func(string)) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if got := waitOperation(t, s, c, op); got.State != "succeeded" {
		t.Fatal(got)
	}
}

// A dedicated, externally prepared <=64MiB filesystem is required. This never
// fills the developer's ordinary home or simulates an ENOSPC return value.
func TestActualIsolatedFilesystemENOSPCNativeCreate(t *testing.T) {
	base := os.Getenv("SILO_TAILD_ENOSPC_ROOT")
	if base == "" {
		t.Skip("isolated filesystem limit unavailable (SILO_TAILD_ENOSPC_ROOT)")
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(base, &stat); err != nil {
		t.Fatal(err)
	}
	if stat.Bsize <= 0 || stat.Blocks > (64<<20)/uint64(stat.Bsize) {
		t.Skip("ENOSPC fixture is not a bounded <=64MiB filesystem")
	}
	home, err := os.MkdirTemp(base, "taild-enospc-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	root := testfixture.Path(t, "SILO_TEST_RUNTIME_ROOT", true)
	r, err := silo.Open(context.Background(), silo.WithHome(home), silo.WithRuntimeRoot(root))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	disk := filepath.Join(home, "input.raw")
	if err = os.WriteFile(disk, make([]byte, 1<<20), 0600); err != nil {
		t.Fatal(err)
	}
	filler, err := os.Create(filepath.Join(home, "fill"))
	if err != nil {
		t.Fatal(err)
	}
	defer filler.Close()
	block := make([]byte, stat.Bsize)
	for bytes := uint64(0); bytes <= 65<<20; bytes += uint64(len(block)) {
		_, err = filler.Write(block)
		if errors.Is(err, unix.ENOSPC) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !errors.Is(err, unix.ENOSPC) {
		t.Fatal("filesystem did not produce actual ENOSPC")
	}
	m, err := r.CreateMachine(context.Background(), silo.DiskImage(disk), silo.WithName("full"))
	if m != nil {
		_ = m.Close()
	}
	if err == nil {
		t.Fatal("native create unexpectedly succeeded on full filesystem")
	}
	if Categorize(err).Exit == 0 {
		t.Fatal("native error was not surfaced")
	}
}
