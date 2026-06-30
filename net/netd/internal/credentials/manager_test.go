package credentials

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/vandycknick/bentobox/net/netd/internal/gateway/hooks"
	"github.com/vandycknick/bentobox/net/netd/internal/secrets"
)

func TestBasicAuthAppliesPasswordSlotAndOverwritesAuthorization(t *testing.T) {
	manager := NewManager(testSecretStore{
		"basic_auth.git-basic.password": secrets.Plain("stored-password"),
	})
	req := httptest.NewRequest(http.MethodGet, "https://git.example.test/repo", nil)
	req.Header.Set("Authorization", "Bearer guest-token")

	err := manager.Apply(context.Background(), req, &hooks.Credential{Kind: "basic_auth", Name: "git-basic", Username: "octo"})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	username, password, ok := req.BasicAuth()
	if !ok || username != "octo" || password != "stored-password" {
		t.Fatalf("expected stored basic auth, got ok=%v username=%q password=%q", ok, username, password)
	}
}

func TestBearerTokenUsesEnvFallbackAndIdempotencyKey(t *testing.T) {
	t.Setenv(envNameForSlot("bearer_token.github-api.token"), "env-token")
	manager := NewManager(nil)
	req := httptest.NewRequest(http.MethodPost, "https://api.example.test/repos?debug=1", nil)
	req.Header.Set("Authorization", "Bearer guest-token")

	err := manager.Apply(context.Background(), req, &hooks.Credential{Kind: "bearer_token", Name: "github-api", IdempotencyKey: true})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer env-token" {
		t.Fatalf("expected env bearer token, got %q", got)
	}
	if req.Header.Get("Idempotency-Key") == "" {
		t.Fatal("expected idempotency key to be generated")
	}
}

func TestHeaderTokenAppliesTokenSlotAndOverwritesManagedHeader(t *testing.T) {
	manager := NewManager(testSecretStore{
		"header_token.internal-api.token": secrets.Plain("stored-token"),
	})
	req := httptest.NewRequest(http.MethodGet, "https://internal.example.test", nil)
	req.Header.Set("X-Internal-Token", "guest-token")

	err := manager.Apply(context.Background(), req, &hooks.Credential{Kind: "header_token", Name: "internal-api", Header: "X-Internal-Token", Prefix: "Token "})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if got := req.Header.Get("X-Internal-Token"); got != "Token stored-token" {
		t.Fatalf("expected managed header to be overwritten, got %q", got)
	}
}

func TestFileSlotWrongTypeDoesNotFallBackToEnv(t *testing.T) {
	t.Setenv(envNameForSlot("bearer_token.api.token"), "env-token")
	manager := NewManager(testSecretStore{
		"bearer_token.api.token": secrets.OAuth(secrets.OAuthSecret{
			AccessToken:  "wrong",
			RefreshToken: "wrong",
			ExpiresAt:    "2026-06-02T12:00:00Z",
		}),
	})
	req := httptest.NewRequest(http.MethodGet, "https://api.example.test", nil)

	err := manager.Apply(context.Background(), req, &hooks.Credential{Kind: "bearer_token", Name: "api"})
	if err == nil || FailureReason(err) != ReasonSecret {
		t.Fatalf("expected wrong file slot type to fail closed with %q, got %v", ReasonSecret, err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("wrong file slot must not fall back to env injection, got %q", got)
	}
}

func TestRequiredPlainSlotRejectsEmptyFileValue(t *testing.T) {
	manager := NewManager(testSecretStore{
		"bearer_token.api.token": secrets.Plain(""),
	})
	req := httptest.NewRequest(http.MethodGet, "https://api.example.test", nil)

	err := manager.Apply(context.Background(), req, &hooks.Credential{Kind: "bearer_token", Name: "api"})
	if err == nil || FailureReason(err) != ReasonSecret {
		t.Fatalf("expected empty file slot to fail closed with %q, got %v", ReasonSecret, err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("empty file slot must not inject Authorization, got %q", got)
	}
}

func TestGitHubOAuthUsesBearerForAPIAndBasicForSmartHTTP(t *testing.T) {
	manager := NewManager(testSecretStore{
		"github_oauth.personal.oauth": secrets.OAuth(secrets.OAuthSecret{
			AccessToken:  "gh-access-token",
			RefreshToken: "gh-refresh-token",
			ExpiresAt:    "2026-06-02T12:00:00Z",
		}),
	})
	credential := &hooks.Credential{Kind: "github_oauth", Name: "personal"}

	apiReq := httptest.NewRequest(http.MethodGet, "https://api.github.com/repos/acme/widgets", nil)
	apiReq.Header.Set("Authorization", "Bearer guest-token")
	if err := manager.Apply(context.Background(), apiReq, credential); err != nil {
		t.Fatalf("Apply API returned error: %v", err)
	}
	if got := apiReq.Header.Get("Authorization"); got != "Bearer gh-access-token" {
		t.Fatalf("expected GitHub API bearer auth, got %q", got)
	}

	gitReq := httptest.NewRequest(http.MethodGet, "https://github.com/acme/widgets.git/info/refs?service=git-upload-pack", nil)
	gitReq.SetBasicAuth("gituser", "placeholder")
	if err := manager.Apply(context.Background(), gitReq, credential); err != nil {
		t.Fatalf("Apply Git smart HTTP returned error: %v", err)
	}
	username, password, ok := gitReq.BasicAuth()
	if !ok || username != "gituser" || password != "gh-access-token" {
		t.Fatalf("expected GitHub smart HTTP basic auth, got ok=%v username=%q password=%q", ok, username, password)
	}
}

func TestOpenAICodexOAuthInjectsHeadersAndRefreshesExpiredStoreSecret(t *testing.T) {
	store := testSecretStore{
		"openai_codex_oauth.personal.oauth": secrets.OAuth(secrets.OAuthSecret{
			AccessToken:  "old-access-token",
			RefreshToken: "old-refresh-token",
			ExpiresAt:    "2026-06-02T11:59:00Z",
			AccountID:    "acct_old",
			CreatedAt:    "2026-06-02T11:00:00Z",
			UpdatedAt:    "2026-06-02T11:00:00Z",
		}),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if err := req.ParseForm(); err != nil {
			t.Fatalf("ParseForm returned error: %v", err)
		}
		if req.Form.Get("grant_type") != "refresh_token" || req.Form.Get("refresh_token") != "old-refresh-token" {
			t.Fatalf("unexpected refresh form: %v", req.Form)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"new-access-token","refresh_token":"new-refresh-token","expires_in":3600}`)
	}))
	defer server.Close()
	manager := NewManager(store)
	manager.client = server.Client()
	manager.openAITokenURL = server.URL
	manager.now = func() time.Time { return mustTime(t, "2026-06-02T12:00:00Z") }
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/conversation", nil)
	req.Header.Set("Authorization", "Bearer guest-token")
	req.Header.Set("ChatGPT-Account-Id", "guest-account")

	err := manager.Apply(context.Background(), req, &hooks.Credential{Kind: "openai_codex_oauth", Name: "personal"})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer new-access-token" {
		t.Fatalf("expected refreshed OpenAI auth header, got %q", got)
	}
	if got := req.Header.Get("ChatGPT-Account-Id"); got != "acct_old" {
		t.Fatalf("expected account id to be preserved, got %q", got)
	}
	updated, err := store.Get("openai_codex_oauth.personal.oauth")
	if err != nil {
		t.Fatalf("Get updated OAuth returned error: %v", err)
	}
	oauth, err := updated.OAuth()
	if err != nil {
		t.Fatalf("OAuth returned error: %v", err)
	}
	if oauth.AccessToken != "new-access-token" || oauth.RefreshToken != "new-refresh-token" || oauth.UpdatedAt != "2026-06-02T12:00:00Z" {
		t.Fatalf("expected refreshed store secret, got %#v", oauth)
	}
}

func TestAWSCredentialSignsWithStaticSlots(t *testing.T) {
	manager := NewManager(testSecretStore{
		"aws_credential.prod.access_key_id":     secrets.Plain("AKIASTATIC"),
		"aws_credential.prod.secret_access_key": secrets.Plain("static-secret"),
		"aws_credential.prod.session_token":     secrets.Plain("static-session"),
	})
	manager.now = func() time.Time { return mustTime(t, "2026-06-02T12:00:00Z") }
	req := httptest.NewRequest(http.MethodPost, "https://s3.us-west-2.amazonaws.com/bucket/key", strings.NewReader("hello"))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=PLACEHOLDER/20260602/us-east-1/sts/aws4_request")
	req.Header.Set("X-Amz-Security-Token", "placeholder-session")

	err := manager.Apply(context.Background(), req, &hooks.Credential{Kind: "aws_credential", Name: "prod"})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	authorization := req.Header.Get("Authorization")
	if !strings.Contains(authorization, "Credential=AKIASTATIC/20260602/us-east-1/sts/aws4_request") || !strings.Contains(authorization, "Signature=") {
		t.Fatalf("expected static AWS signature scoped by incoming Authorization, got %q", authorization)
	}
	if strings.Contains(authorization, "PLACEHOLDER") {
		t.Fatalf("placeholder AWS credential leaked into Authorization: %q", authorization)
	}
	if got := req.Header.Get("X-Amz-Security-Token"); got != "static-session" {
		t.Fatalf("expected static session token, got %q", got)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll body returned error: %v", err)
	}
	if string(body) != "hello" {
		t.Fatalf("signing must restore request body, got %q", string(body))
	}
}

func TestAWSCredentialProfileSlotUsesProfileResolver(t *testing.T) {
	manager := NewManager(testSecretStore{
		"aws_credential.prod.profile": secrets.Plain("production-admin"),
	})
	manager.now = func() time.Time { return mustTime(t, "2026-06-02T12:00:00Z") }
	calledProfile := ""
	manager.awsProfileCredentials = func(_ context.Context, profile string) (aws.Credentials, error) {
		calledProfile = profile
		return aws.Credentials{
			AccessKeyID:     "AKIAPROFILE",
			SecretAccessKey: "profile-secret",
			SessionToken:    "profile-session",
		}, nil
	}
	req := httptest.NewRequest(http.MethodGet, "https://dynamodb.us-east-1.amazonaws.com/", nil)

	err := manager.Apply(context.Background(), req, &hooks.Credential{Kind: "aws_credential", Name: "prod"})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if calledProfile != "production-admin" {
		t.Fatalf("expected profile resolver to use production-admin, got %q", calledProfile)
	}
	if authorization := req.Header.Get("Authorization"); !strings.Contains(authorization, "Credential=AKIAPROFILE/20260602/us-east-1/dynamodb/aws4_request") {
		t.Fatalf("expected profile AWS signature, got %q", authorization)
	}
	if got := req.Header.Get("X-Amz-Security-Token"); got != "profile-session" {
		t.Fatalf("expected profile session token, got %q", got)
	}
}

func TestFailureReasonUsesClassifiedApplyError(t *testing.T) {
	err := applyError(ReasonRefresh, "refresh failed")
	if got := FailureReason(err); got != ReasonRefresh {
		t.Fatalf("expected %q, got %q", ReasonRefresh, got)
	}
	var applyErr *ApplyError
	if !errors.As(err, &applyErr) {
		t.Fatalf("expected ApplyError, got %T", err)
	}
	if got := FailureReason(errors.New("plain")); got != ReasonInjection {
		t.Fatalf("expected unclassified errors to map to %q, got %q", ReasonInjection, got)
	}
}

type testSecretStore map[string]secrets.Secret

func (s testSecretStore) Get(name string) (secrets.Secret, error) {
	secret, ok := s[name]
	if !ok {
		return secrets.Secret{}, fmt.Errorf("%w: %q", secrets.ErrNotFound, name)
	}
	return secret, nil
}

func (s testSecretStore) UpdateOAuth(name string, secret secrets.OAuthSecret) error {
	existing, ok := s[name]
	if !ok {
		return fmt.Errorf("%w: %q", secrets.ErrNotFound, name)
	}
	if existing.Type != secrets.TypeOAuth {
		return fmt.Errorf("secret %q has type %q, expected %q", name, existing.Type, secrets.TypeOAuth)
	}
	s[name] = secrets.OAuth(secret)
	return nil
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return parsed
}
