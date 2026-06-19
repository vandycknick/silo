package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vandycknick/bentobox/net/bento-netd/internal/gateway/hooks"
	"github.com/vandycknick/bentobox/net/bento-netd/internal/secrets"
)

func TestManagerInjectsBearerToken(t *testing.T) {
	store := writeSecretStoreForTest(t, map[string]secrets.Secret{
		"api-token": secrets.Plain("host-token"),
	})
	req := httptest.NewRequest(http.MethodGet, "https://api.example.test", nil)
	req.Header.Set("Authorization", "Bearer guest-token")
	manager := NewManager(store)

	err := manager.Apply(context.Background(), req, &hooks.Credential{
		Kind:   kindBearerToken,
		Name:   "api",
		Secret: "api-token",
	})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer host-token" {
		t.Fatalf("expected bearer token injection, got %q", got)
	}
}

func TestManagerRejectsWrongBearerSecretType(t *testing.T) {
	store := writeSecretStoreForTest(t, map[string]secrets.Secret{
		"codex": secrets.OAuth(secrets.OAuthSecret{
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			ExpiresAt:    rfc3339(time.Now().Add(time.Hour)),
		}),
	})
	manager := NewManager(store)
	req := httptest.NewRequest(http.MethodGet, "https://api.example.test", nil)

	err := manager.Apply(context.Background(), req, &hooks.Credential{
		Kind:   kindBearerToken,
		Name:   "api",
		Secret: "codex",
	})
	if err == nil {
		t.Fatal("expected wrong secret type to be rejected")
	}
}

func TestManagerInjectsOpenAICodexOAuthHeaders(t *testing.T) {
	accessToken := fakeJWT(t, map[string]any{"chatgpt_account_id": "acct_123"})
	store := writeSecretStoreForTest(t, map[string]secrets.Secret{
		"codex": secrets.OAuth(secrets.OAuthSecret{
			AccessToken:  accessToken,
			RefreshToken: "refresh-token",
			ExpiresAt:    rfc3339(time.Now().Add(time.Hour)),
			CreatedAt:    rfc3339(time.Now()),
			UpdatedAt:    rfc3339(time.Now()),
		}),
	})
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", nil)
	req.Header.Set("Authorization", "Bearer guest-token")
	req.Header.Set("ChatGPT-Account-Id", "guest-account")

	manager := NewManager(store)
	err := manager.Apply(context.Background(), req, &hooks.Credential{
		Kind:   kindOpenAICodexOAuth,
		Name:   "codex",
		Secret: "codex",
	})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer "+accessToken {
		t.Fatalf("expected OpenAI access token injection, got %q", got)
	}
	if got := req.Header.Get("ChatGPT-Account-Id"); got != "acct_123" {
		t.Fatalf("expected ChatGPT account id injection, got %q", got)
	}
}

func TestManagerRefreshesOpenAICodexOAuthSecret(t *testing.T) {
	fixedNow := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	oldAccessToken := fakeJWT(t, map[string]any{"chatgpt_account_id": "old_account"})
	newAccessToken := fakeJWT(t, map[string]any{
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "new_account"},
	})
	store := writeSecretStoreForTest(t, map[string]secrets.Secret{
		"codex": secrets.OAuth(secrets.OAuthSecret{
			AccessToken:  oldAccessToken,
			RefreshToken: "old-refresh-token",
			ExpiresAt:    rfc3339(fixedNow.Add(-time.Hour)),
			CreatedAt:    rfc3339(fixedNow.Add(-24 * time.Hour)),
			UpdatedAt:    rfc3339(fixedNow.Add(-24 * time.Hour)),
		}),
	})
	var refreshRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshRequests++
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST refresh, got %s", r.Method)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read refresh body: %v", err)
		}
		values, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatalf("parse refresh body: %v", err)
		}
		if got := values.Get("grant_type"); got != "refresh_token" {
			t.Fatalf("expected refresh_token grant, got %q", got)
		}
		if got := values.Get("refresh_token"); got != "old-refresh-token" {
			t.Fatalf("expected old refresh token, got %q", got)
		}
		if got := values.Get("client_id"); got != openAICodexClientID {
			t.Fatalf("expected OpenAI Codex client id, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + newAccessToken + `","refresh_token":"new-refresh-token","expires_in":3600}`))
	}))
	defer server.Close()

	manager := NewManager(store)
	manager.client = server.Client()
	manager.openAITokenURL = server.URL
	manager.now = func() time.Time { return fixedNow }
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", nil)

	err := manager.Apply(context.Background(), req, &hooks.Credential{
		Kind:   kindOpenAICodexOAuth,
		Name:   "codex",
		Secret: "codex",
	})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if refreshRequests != 1 {
		t.Fatalf("expected one refresh request, got %d", refreshRequests)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer "+newAccessToken {
		t.Fatalf("expected refreshed OpenAI access token injection, got %q", got)
	}
	if got := req.Header.Get("ChatGPT-Account-Id"); got != "new_account" {
		t.Fatalf("expected refreshed ChatGPT account id injection, got %q", got)
	}
	refreshed := readOAuthSecretForTest(t, store, "codex")
	if refreshed.AccessToken != newAccessToken {
		t.Fatalf("expected refreshed access token persisted, got %q", refreshed.AccessToken)
	}
	if refreshed.RefreshToken != "new-refresh-token" {
		t.Fatalf("expected refreshed refresh token persisted, got %q", refreshed.RefreshToken)
	}
	if refreshed.ExpiresAt != rfc3339(fixedNow.Add(time.Hour)) {
		t.Fatalf("expected refreshed expiry, got %q", refreshed.ExpiresAt)
	}
	if refreshed.AccountID != "new_account" {
		t.Fatalf("expected derived account id persisted, got %q", refreshed.AccountID)
	}
}

func TestChatGPTAccountIDReadsNestedClaim(t *testing.T) {
	token := fakeJWT(t, map[string]any{
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "acct_nested"},
	})
	if got := chatGPTAccountID(token); got != "acct_nested" {
		t.Fatalf("expected nested account id, got %q", got)
	}
}

func writeSecretStoreForTest(t *testing.T, data map[string]secrets.Secret) *secrets.FileStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.json")
	body, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatalf("encode secret store: %v", err)
	}
	body = append(body, '\n')
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write secret store: %v", err)
	}
	return secrets.NewFileStore(path)
}

func readOAuthSecretForTest(t *testing.T, store secrets.Store, name string) secrets.OAuthSecret {
	t.Helper()
	secret, err := store.Get(name)
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}
	oauth, err := secret.OAuth()
	if err != nil {
		t.Fatalf("read oauth secret: %v", err)
	}
	return oauth
}

func fakeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	if err != nil {
		t.Fatalf("encode jwt header: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("encode jwt payload: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}
