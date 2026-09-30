//go:build silo_e2e

package integration_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/sdk/go"
)

func TestDefaultStoreBearerSecretStartAndAudit(t *testing.T) {
	if os.Getenv("SILO_E2E_KVM") != "1" {
		t.Skip("SILO_E2E_KVM=1 is required for the SDK real-VM secret test")
	}
	if _, err := os.Stat("/dev/kvm"); err != nil {
		t.Fatalf("SILO_E2E_KVM=1 requires /dev/kvm: %v", err)
	}
	runtimeRoot, image := os.Getenv("SILO_TEST_RUNTIME_ROOT"), os.Getenv("SILO_TEST_IMAGE")
	if runtimeRoot == "" || image == "" {
		t.Skip("SILO_TEST_RUNTIME_ROOT and SILO_TEST_IMAGE (with curl) are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 210*time.Second)
	defer cancel()
	home := t.TempDir()
	const token = "synthetic-sdk-secret"
	if err := os.WriteFile(filepath.Join(home, "secrets.json"), []byte(`{"bearer_token.api.token":{"type":"plain","value":"`+token+`"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	runtime, err := silo.Open(ctx, silo.WithHome(home), silo.WithRuntimeRoot(runtimeRoot))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	policy, err := silo.ParseNetworkPolicyJSON(`{"version":1,"endpoints":[{"name":"api","kind":"https","family":"http","transport":"https-mitm","tls":"terminate","capabilities":["credential-injection"],"hosts":["example.com"]}],"credentials":[{"name":"api","kind":"bearer_token","endpoint":"api"}],"rules":[{"endpoints":["api"],"credential":"api","verdict":"allow"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	machine, err := runtime.CreateMachine(ctx, silo.OCIImage(image), silo.WithName("sdk-secret-e2e"), silo.WithVsock(true), silo.WithCPUs(1), silo.WithMemory(silo.Gibibytes(1)), silo.WithMachineNetwork(silo.PrivateNetwork(policy)))
	if err != nil {
		t.Fatal(err)
	}
	defer machine.Close()
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cleanupCancel()
		if _, err := machine.Stop(cleanupCtx); err != nil {
			t.Errorf("stop: %v", err)
		}
		if err := machine.Remove(cleanupCtx); err != nil {
			t.Errorf("remove: %v", err)
		}
	}()
	if _, err := machine.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitForReady(t, ctx, machine)
	output, err := machine.Exec(ctx, "/bin/sh", []string{"-c", "curl --fail --silent --show-error --max-time 20 https://example.com/ >/dev/null"})
	if err != nil {
		t.Fatal(err)
	}
	result := output.Result()
	if result.Code == nil || *result.Code != 0 {
		t.Fatalf("guest request failed: %#v %s", result, output.Stderr())
	}
	logs, err := machine.Logs(ctx, silo.MachineLogNetworkAudit, silo.MachineLogOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer logs.Close()
	var audit strings.Builder
	for {
		chunk, err := logs.Recv(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		audit.Write(chunk.Data)
	}
	if strings.Contains(audit.String(), token) {
		t.Fatal("secret appeared in audit log")
	}
	selected := false
	scanner := bufio.NewScanner(strings.NewReader(audit.String()))
	for scanner.Scan() {
		var event struct {
			Credential *struct {
				Name        string `json:"name"`
				Kind        string `json:"kind"`
				Status      string `json:"status"`
				ErrorReason string `json:"error_reason"`
			} `json:"credential"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		if event.Credential != nil && event.Credential.Name == "api" && event.Credential.Kind == "bearer_token" && event.Credential.Status == "selected" && event.Credential.ErrorReason == "" {
			selected = true
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if !selected {
		t.Fatalf("no successful bearer credential selection in actual netd audit: %s", audit.String())
	}
}
