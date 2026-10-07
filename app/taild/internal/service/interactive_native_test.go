package service

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/enroll"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	"github.com/vandycknick/silo/app/taild/internal/testfixture/daemon"
	silo "github.com/vandycknick/silo/sdk/go"
	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
)

func TestNativeInteractiveCreateBootsWithOfflineControl(t *testing.T) {
	if os.Getenv("SILO_E2E_KVM") != "1" {
		t.Skip("SILO_E2E_KVM=1 required")
	}
	registry := testfixture.OCIRegistry(t, testfixture.Path(t, "SILO_TAILD_TEST_ROOTFS", true))
	s := actualService(t)
	s.Config.VM.AllowedRegistries = []string{registry.Allowed()}
	s.Config.Enrollment.Mode = "interactive"
	s.VMNodesEnabled = true
	s.Enrollment = &enroll.Manager{Config: s.Config, Pin: state.NodePin{Tailnet: "fixture", Suffix: "fixture.test", ControlURL: "http://127.0.0.1:1"}, Registry: enroll.NewRegistry(), Metrics: s.Runtime.Metrics}
	c := domainCaller(s, "user:7")
	ctx := context.Background()
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		entries, err := s.Runtime.Control.Inventory(cleanup)
		if err != nil {
			t.Error(err)
			return
		}
		for _, entry := range entries {
			d, err := s.Runtime.Control.Inspect(cleanup, entry.ID)
			if err != nil {
				t.Error(err)
				continue
			}
			_, _ = s.Runtime.Control.Stop(cleanup, d.ID, d.RunID, silo.StopOptions{Force: true, Timeout: time.Second})
			if err = s.Runtime.Control.Remove(cleanup, d.ID); err != nil {
				t.Error(err)
			}
		}
	})
	// Enabling the service does not opt an ordinary creation into enrollment.
	op, err := s.Create(ctx, c, CreateRequest{Image: registry.Reference, Name: "ordinary", NoStart: true})
	daemon.Succeeded(t, s.Jobs, c.Peer, op, err)
	v, err := s.Show(ctx, c.Peer, "ordinary")
	if err != nil || v.NodeState != state.NoNode {
		t.Fatal(v, err)
	}
	started := time.Now()
	op, err = s.Create(ctx, c, CreateRequest{Image: registry.Reference, Name: "pending", Tailscale: true})
	daemon.Succeeded(t, s.Jobs, c.Peer, op, err)
	result := daemon.WaitOperation(t, s.Jobs, c.Peer, op, nil)
	if result.Completion == nil || !result.Completion.Running || result.Completion.Node != "" || time.Since(started) > 45*time.Second {
		t.Fatal(result, time.Since(started))
	}
	d, err := s.Runtime.Control.Inspect(ctx, "pending")
	if err != nil || d.RunID == nil || d.Network.Tailscale == nil {
		t.Fatal(d, err)
	}
	status := d.NetworkObservation.GetLive()
	if status == nil || status.State == w.NodeState_NODE_STATE_READY {
		t.Fatal("current netd must publish its actual pending state", status)
	}
	var output bytes.Buffer
	code, err := s.Exec(ctx, c, "pending", ExecRequest{Program: "/bin/sh", Args: []string{"-c", "printf usable"}}, IO{Stdout: &output, Stderr: io.Discard})
	if err != nil || code != 0 || output.String() != "usable" {
		t.Fatal("guest unavailable during enrollment", code, err, output.String())
	}
	// The same guest path used by the lobby shell works before tailnet login.
	output.Reset()
	code, err = s.Shell(ctx, c, "pending", "", IO{Stdin: strings.NewReader("printf shell-usable; exit\n"), Stdout: &output, Stderr: io.Discard, Terminal: Terminal{Present: true, Window: Window{Rows: 24, Columns: 80}, Term: "xterm"}})
	if err != nil || code != 0 || !strings.Contains(output.String(), "shell-usable") {
		t.Fatal(code, err, output.String())
	}
	oldRun := *d.RunID
	op, err = s.Restart(ctx, c, "pending")
	daemon.Succeeded(t, s.Jobs, c.Peer, op, err)
	d, err = s.Runtime.Control.Inspect(ctx, d.ID)
	if err != nil || d.RunID == nil || *d.RunID == oldRun {
		t.Fatal(d, err)
	}
	if status := d.NetworkObservation.GetLive(); status != nil && status.RunId == oldRun {
		t.Fatal("old run accepted after restart")
	}
	// A fresh service observer reads the running node without starting enrollment.
	observer := &Service{Runtime: s.Runtime, Audit: s.Audit, Config: s.Config, Jobs: s.Jobs, Enrollment: s.Enrollment}
	v, err = observer.Show(ctx, c.Peer, "pending")
	if err != nil || v.State != silo.MachineStatusRunning || v.Node != "" || v.NodeState == state.NoNode {
		t.Fatal(v, err)
	}
	op, err = s.Stop(ctx, c, "pending", StopRequest{Force: true, Timeout: time.Second})
	daemon.Succeeded(t, s.Jobs, c.Peer, op, err)
	v, err = s.Show(ctx, c.Peer, "pending")
	if err != nil || v.Node != "pending.fixture.test" || v.NodeState != state.NodeState("stopped") {
		t.Fatal("stopped node lost its configured name", v, err)
	}
	if _, err = os.Stat(d.Network.Tailscale.StateDir); err != nil {
		t.Fatal("stop deleted authentication state", err)
	}
	listed, err := s.List(ctx, c.Peer)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range listed {
		if entry.Name == "pending" && (entry.Node != v.Node || entry.NodeState != v.NodeState) {
			t.Fatal("list/show disagree", entry, v)
		}
	}
	op, err = s.Start(ctx, c, "pending")
	daemon.Succeeded(t, s.Jobs, c.Peer, op, err)
	op, err = s.Remove(ctx, c, "pending", RemoveRequest{Force: true})
	daemon.Succeeded(t, s.Jobs, c.Peer, op, err)
}
