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
func TestProviderActualCLI(t *testing.T) {
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
		"version": 2, "store": "file:" + store, "machine": "0123456789abcdef0123456789abcdef", "run": "run", "issued_at": "2026-09-30T00:00:00Z",
		"allowed": []map[string]string{{"slot": "personal.oauth.access_token", "key": "openai_codex_oauth.personal.oauth", "field": "OAuthAccessToken", "backing_scope": "Home"}, {"slot": "personal.oauth.expires_at", "key": "openai_codex_oauth.personal.oauth", "field": "OAuthExpiresAt", "backing_scope": "Home"}, {"slot": "personal.oauth.account_id", "key": "openai_codex_oauth.personal.oauth", "field": "OAuthAccountId", "backing_scope": "Home"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	provider := &Provider{Version: 2, Command: command, Args: []string{"secret", "provide", "--store-file", store}, Grant: grant}
	credential := &hooks.Credential{Name: "personal", Kind: "openai_codex_oauth", Endpoint: "chatgpt"}
	names := []string{"personal.oauth.access_token", "personal.oauth.expires_at", "personal.oauth.account_id"}
	source := NewStatic(map[string][]byte{names[0]: []byte("old-synthetic-token"), names[1]: []byte("2099-01-01T00:00:00Z")}, provider)
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
		if err == nil || err.Error() != "secret provider returned invalid_request" {
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
	if _, err := unauthorized.Refresh(ctx, names, "expired"); err == nil {
		t.Fatalf("actual CLI failed to reject invalid framed grant: %v", err)
	}
	after, err := os.ReadFile(store)
	if err != nil || string(after) != string(before) {
		t.Fatal("denied/invalid refresh changed the actual store")
	}
	valid := []byte(`{"openai_codex_oauth.personal.oauth":{"type":"oauth","access_token":"selected-access","refresh_token":"never-transport-refresh","expires_at":"2099-01-01T00:00:00Z","account_id":"account"}}`)
	if err := os.WriteFile(store, valid, 0600); err != nil {
		t.Fatal(err)
	}
	provider.Grant = grant
	accepted := NewStatic(nil, provider)
	values, err := accepted.Refresh(ctx, names, "expired")
	if err != nil || string(values[names[0]]) != "selected-access" || string(values[names[2]]) != "account" {
		t.Fatalf("actual CLI get failed: %v", err)
	}
	if value, ok := accepted.Lookup(names[0]); !ok || string(value) != "selected-access" {
		t.Fatal("actual CLI values not cached")
	}
	for _, variant := range []string{"name", "store", "scope"} {
		var deniedGrant map[string]any
		if err := json.Unmarshal(grant, &deniedGrant); err != nil {
			t.Fatal(err)
		}
		requested := names
		switch variant {
		case "name":
			requested = []string{names[0], "outside.token"}
		case "store":
			deniedGrant["store"] = "file:" + filepath.Join(dir, "other.json")
		case "scope":
			deniedGrant["allowed"] = []map[string]any{{"slot": names[0], "key": "openai_codex_oauth.personal.oauth", "field": "OAuthAccessToken", "backing_scope": map[string]any{"Machine": map[string]string{"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}}
			requested = names[:1]
		}
		raw, err := json.Marshal(deniedGrant)
		if err != nil {
			t.Fatal(err)
		}
		provider.Grant = raw
		if _, err := NewStatic(nil, provider).Refresh(ctx, requested, "expired"); err == nil {
			t.Fatalf("accepted denied %s", variant)
		}
		after, err := os.ReadFile(store)
		if err != nil || string(after) != string(valid) {
			t.Fatal("denied get changed store")
		}
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
