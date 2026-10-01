package service

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/enroll"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	silo "github.com/vandycknick/silo/sdk/go"
	"golang.org/x/sys/unix"
)

func TestActualCreateControlUnreachableIsBoundedExit9AndResumable(t *testing.T) {
	s := actualService(t)
	registry := testfixture.OCIRegistry(t, "")
	s.Config.VM.DefaultImage = registry.Reference
	s.Config.VM.AllowedRegistries = []string{strings.Split(registry.Reference, "/")[0] + "/fixture"}
	s.Config.Enrollment.Mode = "interactive"
	s.VMNodesEnabled = true
	var requests atomic.Int32
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(503) }))
	defer control.Close()
	s.Enrollment = &enroll.Manager{Config: s.Config, Pin: state.NodePin{Tailnet: "fixture", Suffix: "fixture.test", ControlURL: control.URL}, Registry: enroll.NewRegistry(), Timeout: 750 * time.Millisecond, Metrics: s.Runtime.Metrics}
	c := domainCaller(t, s, "user:1")
	started := time.Now()
	op, err := s.Create(context.Background(), c, CreateRequest{Name: "offline"})
	if err != nil {
		t.Fatal(err)
	}
	finished := waitOperation(t, s, c, op)
	if finished.Error == nil || finished.Error.Exit != 9 || time.Since(started) > 30*time.Second || requests.Load() == 0 {
		t.Fatal(finished, time.Since(started), requests.Load())
	}
	v, err := s.Show(context.Background(), c.Peer, "offline")
	if err != nil || v.State != silo.MachineStatusStopped {
		t.Fatal("not resumable", v, err)
	}
	s.createMu.Lock()
	if len(s.pending) != 0 || len(s.diskPending) != 0 {
		t.Error("quota/disk reservations leaked")
	}
	s.createMu.Unlock()
	// A second real attempt reacquires the lease on the same durable VM.
	op, err = s.Start(context.Background(), c, "offline")
	if err != nil {
		t.Fatal(err)
	}
	if finished = waitOperation(t, s, c, op); finished.Error == nil || finished.Error.Exit != 9 {
		t.Fatal(finished)
	}
	var out bytes.Buffer
	s.Runtime.Metrics.Write(&out)
	for _, metric := range []string{
		`taild_operations_total{kind="create",outcome="failed"} 1`,
		`taild_operations_total{kind="start",outcome="failed"} 1`,
		`taild_enrollment_duration_seconds_count{outcome="failed"} 2`,
		`taild_native_handles{kind="machine",scope="daemon_owned"} 0`,
		`taild_native_handles{kind="node_lease",scope="daemon_owned"} 0`,
	} {
		if !strings.Contains(out.String(), metric) {
			t.Fatal("real operation metric missing", metric, out.String())
		}
	}
	if strings.Contains(out.String(), s.Config.Home) || strings.Contains(out.String(), "offline") || strings.Contains(out.String(), "user:1") {
		t.Fatal("metric label leaked identity")
	}
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
	s.Jobs.Pause()
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
