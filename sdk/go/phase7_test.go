package silo

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func phase7Runtime(t *testing.T) (*Runtime, string) {
	t.Helper()
	root := os.Getenv("SILO_TEST_RUNTIME_ROOT")
	if root == "" {
		t.Skip("SILO_TEST_RUNTIME_ROOT is required for actual native bridge tests")
	}
	home := t.TempDir()
	runtime, err := Open(context.Background(), WithHome(home), WithRuntimeRoot(root))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	return runtime, home
}

func TestPhase7CanonicalDigitNamesAndEscapesThroughNativeHCL(t *testing.T) {
	if os.Getenv("SILO_GO_FFI_PATH") == "" {
		t.Skip("SILO_GO_FFI_PATH is required")
	}
	for _, name := range []string{"1api", "1420"} {
		reason := "quote: \" \\ newline:\n unicode: café literal:${value} %{if value}"
		policy, err := BuildNetworkPolicy(NetworkPolicyConfig{
			Endpoints:   []NetworkEndpoint{{Name: name, Kind: NetworkEndpointHTTPS, Hosts: []string{"api.example.com"}}},
			Credentials: []NetworkCredential{{Name: name, Kind: CredentialBearerToken, Endpoint: &name}},
			Tunnels:     []TailscaleTunnel{{Name: name}},
			Rules:       []NetworkRule{{Endpoints: []string{name}, Credential: &name, Tunnel: &name, Reason: &reason, Verdict: NetworkVerdictAllow}},
		})
		if err != nil {
			t.Fatal(err)
		}
		policy, err = ParseNetworkPolicyJSON(policy.JSON())
		if err != nil {
			t.Fatal(err)
		}
		hcl, err := policy.HCL()
		if err != nil {
			t.Fatal(err)
		}
		for _, kind := range []string{"https", "bearer_token", "tailscale"} {
			if !strings.Contains(hcl, kind+`["`+name+`"]`) {
				t.Fatalf("reference not escaped: %s", hcl)
			}
		}
		loaded, err := ParseNetworkPolicyHCL(hcl)
		if err != nil {
			t.Fatal(err)
		}
		var canonical struct {
			Rules []struct {
				Reason string `json:"reason"`
			} `json:"rules"`
		}
		if err := json.Unmarshal([]byte(loaded.JSON()), &canonical); err != nil {
			t.Fatal(err)
		}
		if len(canonical.Rules) != 1 || canonical.Rules[0].Reason != reason {
			t.Fatalf("string semantics lost: %#v", canonical)
		}
		again, err := loaded.HCL()
		if err != nil || again != hcl {
			t.Fatalf("unstable HCL: %v\n%s", err, again)
		}
	}
}

func TestPhase7NativePolicyAndStoppedMachineContracts(t *testing.T) {
	runtime, home := phase7Runtime(t)
	ctx := context.Background()
	policy, err := ParseNetworkPolicyHCL("tailscale \"vm\" {\n ephemeral = true\n hostname = \"exact\"\n }")
	if err != nil {
		t.Fatal(err)
	}
	hcl, err := policy.HCL()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseNetworkPolicyHCL(hcl)
	if err != nil {
		t.Fatal(err)
	}
	again, err := parsed.HCL()
	if err != nil || again != hcl {
		t.Fatalf("non-deterministic HCL: %v", err)
	}
	metadata, err := policy.SecretMetadata()
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.Slots) != 1 || metadata.Slots[0].Required {
		t.Fatalf("optional tailscale slots: %#v", metadata)
	}
	ready, err := runtime.PolicySecretsReady(ctx, policy, "")
	if err != nil || !ready {
		t.Fatalf("optional key readiness: %v %v", ready, err)
	}
	disk := filepath.Join(home, "input.raw")
	if err := os.WriteFile(disk, []byte("root-disk"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.CreateMachine(ctx, DiskImage(disk), WithName("without-vsock"), WithMachineNetwork(PrivateNetwork(policy))); err == nil {
		t.Fatal("Tailscale accepted without vsock")
	}
	machine, err := runtime.CreateMachine(ctx, DiskImage(disk), WithName("exact"), WithVsock(true), WithMachineNetwork(PrivateNetwork(policy)))
	if err != nil {
		t.Fatal(err)
	}
	defer machine.Close()
	data, err := machine.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if data.GuestUser == nil || data.GuestUser.Name != "silo" || data.GuestUser.UID != 1000 || data.GuestUser.GID != 1000 || data.GuestUser.Home != "/home/silo" {
		t.Fatalf("guest defaults: %#v", data.GuestUser)
	}
	if data.CPUs == nil || data.Memory == nil {
		t.Fatal("missing hardware read model")
	}
	tailscale := data.Network.Tailscale
	if tailscale == nil || !tailscale.Ephemeral || tailscale.Hostname != "exact" {
		t.Fatalf("tailscale read model: %#v", tailscale)
	}
	info, err := os.Stat(tailscale.StateDir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("state permissions: %v %v", info, err)
	}
	name := "renamed"
	labels := map[string]string{"io.silo.taild.name": name}
	disabled := false
	if _, err := machine.Update(ctx, MachineUpdate{Name: &name, Labels: &labels, ClearPolicy: true}); err == nil {
		t.Fatal("rename accepted while current Tailscale policy was cleared")
	}
	if _, err := machine.Update(ctx, MachineUpdate{Vsock: &disabled}); err == nil {
		t.Fatal("vsock disable accepted")
	}
	if _, err := machine.Update(ctx, MachineUpdate{ClearPolicy: true}); err != nil {
		t.Fatal(err)
	}
	cpus := uint8(2)
	memory := Mebibytes(256)
	forwards := []Forward{}
	data, err = machine.Update(ctx, MachineUpdate{Name: &name, Labels: &labels, CPUs: &cpus, Memory: &memory, Vsock: &disabled, Forwards: &forwards})
	if err != nil {
		t.Fatal(err)
	}
	if data.Name != name || data.Labels["io.silo.taild.name"] != name || data.CPUs == nil || *data.CPUs != cpus || data.Memory == nil || data.Memory.Bytes() != memory.Bytes() {
		t.Fatalf("durable update: %#v", data)
	}
	zero := uint8(0)
	if _, err := machine.Update(ctx, MachineUpdate{CPUs: &zero}); err == nil {
		t.Fatal("explicit zero CPU lost")
	}
	shrink := Bytes(1)
	if _, err := machine.Update(ctx, MachineUpdate{RootDiskSize: &shrink}); err == nil {
		t.Fatal("disk shrink accepted")
	}
	reopened, err := Open(ctx, WithHome(home), WithRuntimeRoot(os.Getenv("SILO_TEST_RUNTIME_ROOT")))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	handle, err := reopened.Machine(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	persisted, err := handle.Inspect(ctx)
	if err != nil || persisted.Labels["io.silo.taild.name"] != name {
		t.Fatalf("atomic reopened identity: %v %v", persisted, err)
	}
	if _, err := machine.StopWith(ctx, StopOptions{Timeout: time.Millisecond, Force: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := machine.WaitReady(ctx, time.Second); err == nil {
		t.Fatal("stopped machine reported ready")
	}
	if err := machine.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tailscale.StateDir); !os.IsNotExist(err) {
		t.Fatalf("tailscale cleanup: %v", err)
	}
}

func TestPhase7ResolverPrecedenceAndResilientInventory(t *testing.T) {
	runtime, home := phase7Runtime(t)
	ctx := context.Background()
	policy, err := ParseNetworkPolicyHCL(`endpoint "https" "api" { hosts = ["api.example.com"] }
credential "bearer_token" "token" { endpoint = https.api }
rule "access" {
endpoint = https.api
credential = bearer_token.token
verdict = "allow"
}`)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := runtime.PolicySecretsReady(ctx, policy, "")
	if err != nil || ready {
		t.Fatalf("missing readiness: %v %v", ready, err)
	}
	secrets := filepath.Join(home, "secrets.json")
	if err := os.WriteFile(secrets, []byte(`{"bearer_token.token.token":{"type":"plain","value":"synthetic-home"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	ready, err = runtime.PolicySecretsReady(ctx, policy, "")
	if err != nil || !ready {
		t.Fatalf("home readiness: %v %v", ready, err)
	}
	disk := filepath.Join(home, "input.raw")
	if err := os.WriteFile(disk, []byte("root-disk"), 0600); err != nil {
		t.Fatal(err)
	}
	good, err := runtime.CreateMachine(ctx, DiskImage(disk), WithName("healthy"))
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	bad, err := runtime.CreateMachine(ctx, DiskImage(disk), WithName("broken"))
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	data, err := bad.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	machineSecrets := filepath.Join(data.MachineDir, "secrets.json")
	if err := os.WriteFile(machineSecrets, []byte(`{"token.token":{"type":"plain","value":""}}`), 0600); err != nil {
		t.Fatal(err)
	}
	ready, err = runtime.PolicySecretsReady(ctx, policy, bad.ID())
	if err != nil || ready {
		t.Fatalf("selected invalid machine override must fail: %v %v", ready, err)
	}
	if err := os.WriteFile(secrets, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	ready, err = runtime.PolicySecretsReady(ctx, policy, "")
	if err != nil || ready {
		t.Fatalf("corrupt store readiness: %v %v", ready, err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 stdlib sqlite3 is required for real corrupt-record inventory coverage")
	}
	output, err := exec.Command(python, "-c", `import sqlite3,sys
db=sqlite3.connect(sys.argv[1])
db.execute("UPDATE machine_config SET config_json=x'00' WHERE name='broken'")
db.commit()`, filepath.Join(home, "state.db")).CombinedOutput()
	if err != nil {
		t.Fatalf("corrupt actual SQLite record: %v %s", err, output)
	}
	entries, err := runtime.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("inventory lost entries: %#v", entries)
	}
	for _, entry := range entries {
		if entry.ID == bad.ID() && len(entry.Issues) == 0 {
			t.Fatal("broken record missing issues")
		}
		if entry.ID == good.ID() && entry.Data == nil {
			t.Fatal("healthy record lost")
		}
	}
}

func TestPhase7ConcurrentExactNames(t *testing.T) {
	runtime, home := phase7Runtime(t)
	ctx := context.Background()
	disk := filepath.Join(home, "input.raw")
	if err := os.WriteFile(disk, []byte("root-disk"), 0600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan *Machine, 6)
	failures := make(chan error, 6)
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			machine, err := runtime.CreateMachine(ctx, DiskImage(disk), WithName("exact-race"))
			if err != nil {
				failures <- err
			} else {
				results <- machine
			}
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	count := 0
	for machine := range results {
		count++
		data, err := machine.Inspect(ctx)
		if err != nil || data.Name != "exact-race" {
			t.Fatalf("surprise name: %v %v", data, err)
		}
		_ = machine.Close()
	}
	if count != 1 {
		t.Fatalf("exact-name winners = %d", count)
	}
	for err := range failures {
		if !strings.Contains(err.Error(), "already exists") {
			t.Fatal(err)
		}
	}
}

func TestPhase7NativeAlternativeAndProjectionReadiness(t *testing.T) {
	runtime, home := phase7Runtime(t)
	ctx := context.Background()
	source := `endpoint "https" "aws" { hosts = ["sts.amazonaws.com"] }
credential "aws_credential" "account" { endpoint = https.aws }
rule "access" {
 endpoint = https.aws
 credential = aws_credential.account
 verdict = "allow"
}`
	policy, err := ParseNetworkPolicyHCL(source)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := policy.SecretMetadata()
	if err != nil || len(metadata.Requirements) != 1 || len(metadata.Requirements[0].Alternatives) != 2 {
		t.Fatalf("AWS alternatives: %#v %v", metadata, err)
	}
	path := filepath.Join(home, "secrets.json")
	if err := os.WriteFile(path, []byte(`{"aws_credential.account.profile":{"type":"plain","value":"synthetic-profile"},"aws_credential.account.access_key_id":{"type":"oauth","access_token":"stale"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	ready, err := runtime.PolicySecretsReady(ctx, policy, "")
	if err != nil || !ready {
		t.Fatalf("profile must suppress stale static key: %v %v", ready, err)
	}
	oauth, err := ParseNetworkPolicyHCL(`endpoint "https" "api" { hosts = ["api.github.com"] }
credential "github_oauth" "github" { endpoint = https.api }
rule "access" {
 endpoint = https.api
 credential = github_oauth.github
 verdict = "allow"
}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"github_oauth.github.oauth":{"type":"oauth","access_token":"synthetic-projected-token","refresh_token":"synthetic-refresh","expires_at":"2027-09-30T00:00:00Z"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	ready, err = runtime.PolicySecretsReady(ctx, oauth, "")
	if err != nil || !ready {
		t.Fatalf("actual OAuth projections: %v %v", ready, err)
	}
	metadata, err = oauth.SecretMetadata()
	if err != nil {
		t.Fatal(err)
	}
	for _, slot := range metadata.Slots {
		if strings.Contains(slot.Name, "synthetic") || strings.Contains(slot.Source.Key, "synthetic") {
			t.Fatal("secret exposed in metadata")
		}
	}
}
