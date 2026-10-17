package silo

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckPolicySecretsNativeDiagnosticsAndScope(t *testing.T) {
	r, home := phase7Runtime(t)
	ctx := context.Background()
	p, e := ParseNetworkPolicyHCL(`endpoint "https" "api" { hosts = ["example.com"] }
credential "bearer_token" "github-api" { endpoint = https.api }
tailscale "vm" {}`)
	if e != nil {
		t.Fatal(e)
	}
	check, e := r.CheckPolicySecrets(ctx, p, "", nil)
	if e != nil || check.Status != PolicySecretsMissing || len(check.Slots) != 1 || check.Slots[0].Name != "github-api.token" || check.Slots[0].Source.Key != "bearer_token.github-api.token" || len(check.Requirements) != 1 {
		t.Fatalf("%+v %v", check, e)
	}
	write := func(path, value string) {
		t.Helper()
		if e := os.WriteFile(path, []byte(value), 0600); e != nil {
			t.Fatal(e)
		}
	}
	path := filepath.Join(home, "secrets.json")
	write(path, `{corrupt-secret-value`)
	check, e = r.CheckPolicySecrets(ctx, p, "", nil)
	if e != nil || check.Status != PolicySecretsUnavailable || check.Code != "invalid_request" || check.Slot == "" || check.Key == "" {
		t.Fatalf("%+v %v", check, e)
	}
	b, _ := json.Marshal(check)
	if strings.Contains(string(b), home) || strings.Contains(string(b), "corrupt-secret-value") {
		t.Fatal(string(b))
	}
	// Whole-set overrides bypass the corrupt store just as at Start, optional key
	// absent, without claiming an incomplete override merges with stored material.
	check, e = r.CheckPolicySecrets(ctx, p, "", map[string]string{"github-api.token": "synthetic"})
	if e != nil || check.Status != PolicySecretsReady {
		t.Fatal(check, e)
	}
	write(path, `{"bearer_token.github-api.token":{"type":"plain","value":"synthetic-home"}}`)
	check, e = r.CheckPolicySecrets(ctx, p, "", nil)
	if e != nil || check.Status != PolicySecretsReady {
		t.Fatal(check, e)
	}
	disk := filepath.Join(home, "source.raw")
	write(disk, "never booted disk fixture")
	m, e := r.CreateMachine(ctx, DiskImage(disk), WithName("scope-check"), WithVsock(true))
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	defer m.Remove(ctx)
	d, e := m.Inspect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	machinePath := filepath.Join(d.MachineDir, "secrets.json")
	write(machinePath, `{"github-api.token":{"type":"plain","value":"synthetic-machine"}}`)
	write(path, `{corrupt-home`)
	// The optional Tailscale slot still probes Home, so use a policy without TS
	// to isolate the winning Machine projection precedence over corrupt Home.
	hcl, e := p.HCL()
	if e != nil {
		t.Fatal(e)
	}
	_ = hcl
	local, e := ParseNetworkPolicyHCL(`endpoint "https" "api" { hosts = ["example.com"] }
credential "bearer_token" "github-api" { endpoint = https.api }`)
	if e != nil {
		t.Fatal(e)
	}
	check, e = r.CheckPolicySecrets(ctx, local, m.ID(), nil)
	if e != nil || check.Status != PolicySecretsReady {
		t.Fatal(check, e)
	}
	check, e = r.CheckPolicySecrets(ctx, local, "", nil)
	if e != nil || check.Status != PolicySecretsUnavailable {
		t.Fatal(check, e)
	}
	write(machinePath, `{"github-api.token":{"type":"plain","value":""}}`)
	check, e = r.CheckPolicySecrets(ctx, local, m.ID(), nil)
	if e != nil || check.Status != PolicySecretsUnavailable || check.Code != "empty_value" {
		t.Fatal(check, e)
	}
	aws, e := ParseNetworkPolicyHCL(`endpoint "https" "aws" { hosts = ["*.amazonaws.com"] }
credential "aws_credential" "work" { endpoint = https.aws }`)
	if e != nil {
		t.Fatal(e)
	}
	write(path, `{"work.profile":{"type":"plain","value":"dev"},"work.access_key_id":{"type":"oauth","access_token":"stale"}}`)
	check, e = r.CheckPolicySecrets(ctx, aws, "", nil)
	if e != nil || check.Status != PolicySecretsReady {
		t.Fatal(check, e)
	}
	write(path, `{}`)
	check, e = r.CheckPolicySecrets(ctx, aws, "", nil)
	if e != nil || check.Status != PolicySecretsMissing || len(check.Requirements) != 1 || len(check.Requirements[0].Alternatives) != 2 {
		t.Fatal(check, e)
	}
}
