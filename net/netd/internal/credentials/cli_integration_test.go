package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/net/netd/internal/gateway/hooks"
	"golang.org/x/sys/unix"
)

// The optional gate selects a built product CLI, never this Go test executable.
// A configured but invalid binary is a failure, not an unavailable prerequisite.
func TestV1ProviderActualCLI(t *testing.T) {
	command := os.Getenv("SILO_TEST_CLI_BIN")
	if command == "" {
		t.Skip("SILO_TEST_CLI_BIN unset: actual built silo CLI required")
	}
	if !filepath.IsAbs(command) {
		t.Fatal("SILO_TEST_CLI_BIN must be absolute")
	}
	binary, err := os.Stat(command)
	if err != nil || !binary.Mode().IsRegular() || binary.Mode().Perm()&0111 == 0 {
		t.Fatalf("invalid actual CLI binary %q: %v", command, err)
	}
	dir := t.TempDir()
	store := filepath.Join(dir, "launch-specific-store.json")
	// A plain record guarantees that an authorized request returns invalid_request
	// without contacting a real OAuth service or needing any live credentials.
	before := []byte(`{"openai_codex_oauth.personal.oauth":{"type":"plain","value":"synthetic-private-token"}}`)
	if err := os.WriteFile(store, before, 0600); err != nil {
		t.Fatal(err)
	}
	grant, err := json.Marshal(map[string]any{
		"version": 1, "store_file": store,
		"credentials": []map[string]string{{"name": "personal", "kind": "openai_codex_oauth", "endpoint": "chatgpt", "secret_key": "openai_codex_oauth.personal.oauth"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	provider := &Provider{Version: 1, Command: command, Args: []string{"secret", "refresh-oauth", "--store-file", store}, Grant: grant}
	credential := &hooks.Credential{Name: "personal", Kind: "openai_codex_oauth", Endpoint: "chatgpt"}
	names := []string{"personal.oauth.access_token", "personal.oauth.expires_at", "personal.oauth.account_id"}
	source := NewStatic(map[string][]byte{names[0]: []byte("old-synthetic-token"), names[1]: []byte("2099-01-01T00:00:00Z")}, provider)
	source.BindCredential(credential)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Block the real CLI inside its store transaction so Linux can inspect the
	// actual product process, rather than accepting a helper's environment claim.
	lock, err := os.OpenFile(store+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	done := make(chan error, 1)
	go func() { _, err := source.Refresh(ctx, names, "expired"); done <- err }()
	if runtime.GOOS == "linux" {
		assertActualCLIEnvironment(t, binary, grant, done)
	} else {
		t.Log("actual CLI provider invocation runs; /proc environment inspection is Linux-only")
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || err.Error() != "oauth refresh hook returned invalid_request" {
			t.Fatalf("actual CLI did not accept framed raw grant: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("actual CLI refresh did not finish")
	}
	manager := NewManager(source)
	request := httptest.NewRequest(http.MethodGet, "https://chatgpt.com/", nil)
	manager.now = func() time.Time { return mustTime(t, "2098-12-31T23:59:00Z") }
	if err := manager.Apply(ctx, request, credential); err != nil || request.Header.Get("Authorization") != "Bearer old-synthetic-token" {
		t.Fatalf("actual CLI proactive failure lost usable credential: %v", err)
	}
	manager.now = func() time.Time { return mustTime(t, "2099-01-01T00:01:00Z") }
	request = httptest.NewRequest(http.MethodGet, "https://chatgpt.com/", nil)
	if err := manager.Apply(ctx, request, credential); err == nil || request.Header.Get("Authorization") != "" {
		t.Fatal("actual CLI failure did not fail closed for expired token")
	}
	provider.Grant = []byte("not-json-raw-auth")
	unauthorized := NewStatic(nil, provider)
	unauthorized.BindCredential(credential)
	if _, err := unauthorized.Refresh(ctx, names, "expired"); err == nil || err.Error() != "oauth refresh hook returned unauthorized" {
		t.Fatalf("actual CLI failed to reject invalid framed grant: %v", err)
	}
	after, err := os.ReadFile(store)
	if err != nil || string(after) != string(before) {
		t.Fatal("denied/invalid refresh changed the actual store")
	}
}

func assertActualCLIEnvironment(t *testing.T, binary os.FileInfo, grant []byte, done <-chan error) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("provider exited before actual environment inspection: %v", err)
		default:
		}
		threads, err := os.ReadDir("/proc/self/task")
		if err != nil {
			t.Fatal(err)
		}
		for _, thread := range threads {
			children, err := os.ReadFile(filepath.Join("/proc/self/task", thread.Name(), "children"))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, pid := range strings.Fields(string(children)) {
				root := filepath.Join("/proc", pid)
				executable, err := os.Stat(filepath.Join(root, "exe"))
				if err != nil || !os.SameFile(binary, executable) {
					continue
				}
				environment, err := os.ReadFile(filepath.Join(root, "environ"))
				if err != nil || len(environment) != 0 {
					t.Fatalf("actual CLI environment was not empty: %v", err)
				}
				argv, err := os.ReadFile(filepath.Join(root, "cmdline"))
				if err != nil || strings.Contains(string(argv), string(grant)) || strings.Contains(string(argv), "synthetic-private-token") {
					t.Fatalf("actual CLI argv contains secret material: %v", err)
				}
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("actual silo CLI child was not observed within 3 seconds")
}
