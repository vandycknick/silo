package state

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	silo "github.com/vandycknick/silo/sdk/go"
)

func TestNativeCrashTransactionFence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if home := os.Getenv("SILO_NODE_CRASH_HOME"); home != "" {
		sdk, e := silo.Open(ctx, silo.WithHome(home), silo.WithRuntimeRoot(os.Getenv("SILO_TEST_RUNTIME_ROOT")))
		if e != nil {
			t.Fatal(e)
		}
		defer sdk.Close()
		machine, e := sdk.Machine(ctx, "dev")
		if e != nil {
			t.Fatal(e)
		}
		defer machine.Close()
		data, e := machine.Inspect(ctx)
		if e != nil {
			t.Fatal(e)
		}
		lease, e := machine.LeaseNodeState(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer lease.Close()
		dir := data.Network.Tailscale.StateDir
		if e = BeginNodeTransaction(dir); e != nil {
			t.Fatal(e)
		}
		step := os.Getenv("SILO_NODE_CRASH_STEP")
		if step != "fence-only" {
			writeNode(t, dir+".pending", "dev")
			if step != "unverified" {
				if e = MarkVerifiedNode(dir + ".pending"); e != nil {
					t.Fatal(e)
				}
			}
		}
		if step == "after-backup" || step == "after-promotion" {
			if e = os.Rename(dir, dir+".backup"); e != nil {
				t.Fatal(e)
			}
			if e = SyncDir(filepath.Dir(dir)); e != nil {
				t.Fatal(e)
			}
		}
		if step == "after-promotion" {
			if e = os.Rename(dir+".pending", dir); e != nil {
				t.Fatal(e)
			}
			if e = SyncDir(filepath.Dir(dir)); e != nil {
				t.Fatal(e)
			}
		}
		if e = SyncDir(filepath.Dir(dir)); e != nil {
			t.Fatal(e)
		}
		fmt.Println("transaction-ready")
		<-ctx.Done()
		t.Fatal("parent did not crash the writer")
	}
	root := testfixture.Path(t, "SILO_TEST_RUNTIME_ROOT", true)
	for _, step := range []string{"fence-only", "before-backup", "after-backup", "after-promotion", "unverified"} {
		t.Run(step, func(t *testing.T) {
			home := t.TempDir()
			sdk, e := silo.Open(ctx, silo.WithHome(home), silo.WithRuntimeRoot(root))
			if e != nil {
				t.Fatal(e)
			}
			defer sdk.Close()
			disk := filepath.Join(home, "root.raw")
			if e = os.WriteFile(disk, []byte("stopped fixture"), 0600); e != nil {
				t.Fatal(e)
			}
			policy, e := silo.ParseNetworkPolicyHCL(`tailscale "vm" { hostname = "dev" }`)
			if e != nil {
				t.Fatal(e)
			}
			machine, e := sdk.CreateMachine(ctx, silo.DiskImage(disk), silo.WithName("dev"), silo.WithVsock(true), silo.WithMachineNetwork(silo.PrivateNetwork(policy)))
			if e != nil {
				t.Fatal(e)
			}
			defer machine.Close()
			data, e := machine.Inspect(ctx)
			if e != nil {
				t.Fatal(e)
			}
			dir := data.Network.Tailscale.StateDir
			// Public serialization fixtures, not a claim of registered control-plane state.
			writeNode(t, dir, "dev")
			exe, e := os.Executable()
			if e != nil {
				t.Fatal(e)
			}
			child := exec.CommandContext(ctx, exe, "-test.run=^TestNativeCrashTransactionFence$", "-test.timeout=30s")
			child.Env = append(os.Environ(), "SILO_NODE_CRASH_HOME="+home, "SILO_NODE_CRASH_STEP="+step)
			output, e := child.StdoutPipe()
			if e != nil {
				t.Fatal(e)
			}
			child.Stderr = os.Stderr
			if e = child.Start(); e != nil {
				t.Fatal(e)
			}
			defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
			scanner := bufio.NewScanner(output)
			ready := false
			for scanner.Scan() {
				if scanner.Text() == "transaction-ready" {
					ready = true
					break
				}
			}
			if !ready {
				t.Fatal("crash writer did not prepare transaction")
			}
			if e = child.Process.Kill(); e != nil {
				t.Fatal(e)
			}
			if e = child.Wait(); e == nil {
				t.Fatal("writer exited without a crash")
			}
			assertFenced := func() {
				t.Helper()
				if _, e = machine.Inspect(ctx); e != nil {
					t.Fatal("inspection fenced", e)
				}
				if _, e = machine.Start(ctx); !silo.IsErrorKind(e, silo.ErrorInvalidMachineUpdate) {
					t.Fatal("native Start bypassed crashed transaction", e)
				}
				cpus := uint8(2)
				if _, e = machine.Update(ctx, silo.MachineUpdate{CPUs: &cpus}); !silo.IsErrorKind(e, silo.ErrorInvalidMachineUpdate) {
					t.Fatal("native Update bypassed crashed transaction", e)
				}
			}
			assertFenced()
			lease, e := machine.LeaseNodeState(ctx)
			if e != nil {
				t.Fatal("recovery lease blocked", e)
			}
			result := RecoverNode(dir, "dev", "user:123", nil)
			lease.Close()
			if step == "unverified" {
				if result != Unreadable {
					t.Fatal("unverified state admitted", result)
				}
				assertFenced()
				if _, e = os.Stat(dir + ".pending"); e != nil {
					t.Fatal("unverified state erased", e)
				}
				// Explicit local removal discards abandoned state; only
				// start/update require recovery before reusing it.
				if e = machine.Remove(ctx); e != nil {
					t.Fatal("local removal of abandoned state failed", e)
				}
				for _, path := range []string{dir, dir + ".pending", dir + ".transaction"} {
					if _, e = os.Stat(path); !os.IsNotExist(e) {
						t.Fatal("removed machine retained abandoned state", path, e)
					}
				}
				return
			}
			if result != Enrolled {
				t.Fatal("verified transaction not recovered", result)
			}
			if _, e = os.Stat(dir + ".transaction"); !os.IsNotExist(e) {
				t.Fatal("committed fence retained", e)
			}
			cpus := uint8(2)
			if _, e = machine.Update(ctx, silo.MachineUpdate{CPUs: &cpus}); e != nil {
				t.Fatal("committed state still fenced", e)
			}
			if e = machine.Remove(ctx); e != nil {
				t.Fatal(e)
			}
		})
	}
}
