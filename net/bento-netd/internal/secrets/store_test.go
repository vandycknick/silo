package secrets

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFileStoreReadsSharedFixture(t *testing.T) {
	store := NewFileStore(filepath.Join("..", "..", "..", "..", "testdata", "secrets", "basic.json"))

	plain, err := store.Get("something")
	if err != nil {
		t.Fatalf("Get plain returned error: %v", err)
	}
	value, err := plain.PlainValue()
	if err != nil {
		t.Fatalf("PlainValue returned error: %v", err)
	}
	if value != "123" {
		t.Fatalf("expected plain value, got %q", value)
	}
	oauth, err := store.Get("openai_codex_oauth.personal.oauth")
	if err != nil {
		t.Fatalf("Get oauth returned error: %v", err)
	}
	token, err := oauth.OAuth()
	if err != nil {
		t.Fatalf("OAuth returned error: %v", err)
	}
	if token.AccessToken != "access-token" || token.RefreshToken != "refresh-token" {
		t.Fatalf("unexpected oauth token: %#v", token)
	}
}

func TestFileStoreUpdatesExistingOAuthSecret(t *testing.T) {
	path := writeStoreForTest(t, map[string]Secret{
		"codex": OAuth(OAuthSecret{
			AccessToken:  "old-access",
			RefreshToken: "old-refresh",
			ExpiresAt:    "2026-06-02T12:00:00Z",
			CreatedAt:    "2026-06-02T11:00:00Z",
			UpdatedAt:    "2026-06-02T11:00:00Z",
		}),
	})
	store := NewFileStore(path)

	err := store.UpdateOAuth("codex", OAuthSecret{
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
		ExpiresAt:    "2026-06-02T13:00:00Z",
		AccountID:    "acct_123",
		CreatedAt:    "2026-06-02T11:00:00Z",
		UpdatedAt:    "2026-06-02T12:00:00Z",
	})
	if err != nil {
		t.Fatalf("UpdateOAuth returned error: %v", err)
	}

	mode := fileModeForTest(t, path)
	if mode != 0o600 {
		t.Fatalf("expected secret store mode 0600, got %o", mode)
	}
	secret, err := store.Get("codex")
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	oauth, err := secret.OAuth()
	if err != nil {
		t.Fatalf("OAuth returned error: %v", err)
	}
	if oauth.AccessToken != "new-access" || oauth.AccountID != "acct_123" {
		t.Fatalf("expected updated oauth secret, got %#v", oauth)
	}
}

func TestFileStoreRejectsOAuthUpdateForPlainSecret(t *testing.T) {
	path := writeStoreForTest(t, map[string]Secret{"api": Plain("token")})
	store := NewFileStore(path)

	err := store.UpdateOAuth("api", OAuthSecret{
		AccessToken:  "access",
		RefreshToken: "refresh",
		ExpiresAt:    "2026-06-02T12:00:00Z",
	})
	if err == nil {
		t.Fatal("expected plain secret update to be rejected")
	}
}

func writeStoreForTest(t *testing.T, secrets map[string]Secret) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.json")
	body, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		t.Fatalf("encode store: %v", err)
	}
	body = append(body, '\n')
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write store: %v", err)
	}
	return path
}

func fileModeForTest(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat store: %v", err)
	}
	return info.Mode().Perm()
}
