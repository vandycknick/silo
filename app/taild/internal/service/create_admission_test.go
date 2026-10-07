package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/enroll"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	"github.com/vandycknick/silo/app/taild/internal/testfixture/daemon"
	silo "github.com/vandycknick/silo/sdk/go"
)

func TestCreateAdmissionFinalizerWithActualHome(t *testing.T) {
	registry := testfixture.OCIRegistry(t, "")
	s := actualService(t)
	s.Config.VM.AllowedRegistries = []string{registry.Allowed()}
	c := domainCaller(s, "user:1")
	checkReleased := func(name string) {
		t.Helper()
		s.createMu.Lock()
		pending, disks := len(s.pending), len(s.diskPending)
		s.createMu.Unlock()
		if pending != 0 || disks != 0 {
			t.Fatal("leaked admission", pending, disks)
		}
		release, err := s.Runtime.Reserve(t.Context(), name, nil)
		if err != nil {
			t.Fatal("leaked name", err)
		}
		release()
		entries, err := s.Runtime.Control.Inventory(t.Context())
		if err != nil || len(entries) != 0 {
			t.Fatal("submission/cancellation created durable records", entries, err)
		}
	}
	s.Jobs.Seal()
	op, err := s.Create(t.Context(), c, CreateRequest{Image: registry.Reference, Name: "submission-failed", NoStart: true})
	if err == nil || op.ID != "" {
		t.Fatal(op, err)
	}
	checkReleased("submission-failed")
	// Cancel daemon work immediately after publication. Both cancellation branches
	// must release pre-publication resources, regardless of callback scheduling.
	for range 20 {
		ctx, cancel := context.WithCancel(t.Context())
		s.Jobs = jobs.New(ctx, 4)
		c.Resolve = func(ctx context.Context) (identity.Peer, error) { <-ctx.Done(); return c.Peer, ctx.Err() }
		op, err = s.Create(t.Context(), c, CreateRequest{Image: registry.Reference, Name: "cancelled", NoStart: true})
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		finished := daemon.WaitOperation(t, s.Jobs, c.Peer, op, nil)
		if finished.Error == nil {
			t.Fatal("cancelled create succeeded", finished)
		}
		if err := s.Jobs.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
		checkReleased("cancelled")
	}
	if registry.Requests.Load() != 0 {
		t.Fatal("cancelled work pulled OCI", registry.Requests.Load())
	}
}

func TestGeneratedNameNativeRaceKeepsPublishedName(t *testing.T) {
	registry := testfixture.OCIRegistry(t, "")
	s, sdk := actualNativeService(t)
	s.Config.VM.AllowedRegistries = []string{registry.Allowed()}
	c := domainCaller(s, "user:1")
	entered, hold := make(chan struct{}), make(chan struct{})
	var once, releaseOnce sync.Once
	releasePull := func() { releaseOnce.Do(func() { close(hold) }) }
	t.Cleanup(releasePull)
	registry.BeforeManifest = func() { once.Do(func() { close(entered); <-hold }) }
	op, err := s.Create(t.Context(), c, CreateRequest{Image: registry.Reference, NoStart: true})
	if err != nil || op.VM == "" {
		t.Fatal(op, err)
	}
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("OCI pull not reached")
	}
	// A real independent native writer wins the Home name race after publication.
	m, err := sdk.CreateMachine(t.Context(), silo.DiskImage(testfixture.Path(t, "SILO_TEST_LOCAL_DISK", false)), silo.WithName(op.VM))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	releasePull()
	finished := daemon.WaitOperation(t, s.Jobs, c.Peer, op, nil)
	if finished.VM != op.VM || finished.Error == nil || finished.Error.Exit != 5 {
		t.Fatal("published proposal renamed or race hidden", finished)
	}
	entries, err := s.Runtime.Control.Inventory(t.Context())
	if err != nil || len(entries) != 1 || entries[0].Name != op.VM {
		t.Fatal(entries, err)
	}
	s.createMu.Lock()
	pending, disks := len(s.pending), len(s.diskPending)
	s.createMu.Unlock()
	if pending != 0 || disks != 0 {
		t.Fatal("race leaked admission", pending, disks)
	}
	if err = m.Remove(t.Context()); err != nil {
		t.Fatal(err)
	}
	op, err = s.Create(t.Context(), c, CreateRequest{Image: registry.Reference, Name: op.VM, NoStart: true})
	daemon.Succeeded(t, s.Jobs, c.Peer, op, err)
}

func TestCreateMissingImageRejectsBeforeNativeAdmission(t *testing.T) {
	registry := testfixture.OCIRegistry(t, "")
	s := actualService(t)
	s.Config.VM.AllowedRegistries = []string{registry.Allowed()}
	s.Config.Enrollment.Mode = "interactive"
	s.VMNodesEnabled = true
	s.Enrollment = &enroll.Manager{Config: s.Config, Registry: enroll.NewRegistry()}
	c := domainCaller(s, "user:1")
	if _, err := s.Documents(t.Context(), c, "template", "create", "image-free", "", "version: '1'\nresources: {cpus: 1}"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ValidateCreate(t.Context(), c.Peer, CreateRequest{Name: "missing"}); err != errImageMissing {
		t.Fatal("direct admission did not require an image", err)
	}
	for _, q := range []CreateRequest{
		{Name: "missing", NoStart: true},
		{Name: "missing", Template: "image-free", NoStart: true},
		{Name: "missing", Tailscale: true, NoStart: true},
		{NoStart: true},
	} {
		op, err := s.Create(t.Context(), c, q)
		if err != errImageMissing || Categorize(err).Code != "usage" || Categorize(err).Exit != 2 || op.ID != "" || op.VM != "" {
			t.Fatal("missing image was not rejected before publication", op, err)
		}
	}
	if registry.Requests.Load() != 0 || len(s.Jobs.List(c.Peer)) != 0 {
		t.Fatal("missing image started work", registry.Requests.Load(), s.Jobs.List(c.Peer))
	}
	s.createMu.Lock()
	pending, disks := len(s.pending), len(s.diskPending)
	s.createMu.Unlock()
	if pending != 0 || disks != 0 {
		t.Fatal("missing image reserved admission", pending, disks)
	}
	entries, err := s.Runtime.Control.Inventory(t.Context())
	if err != nil || len(entries) != 0 {
		t.Fatal("missing image created durable records", entries, err)
	}
	release, err := s.Runtime.Reserve(t.Context(), "missing", nil)
	if err != nil {
		t.Fatal("missing image reserved a name", err)
	}
	release()
	op, err := s.Create(t.Context(), c, CreateRequest{Name: "missing", Template: "image-free", Image: registry.Reference, NoStart: true})
	daemon.Succeeded(t, s.Jobs, c.Peer, op, err)
}
