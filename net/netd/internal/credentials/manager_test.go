package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/net/netd/internal/gateway/hooks"
)

func TestBasicAuthAppliesPasswordSlotAndOverwritesAuthorization(t *testing.T) {
	manager := NewManager(NewStatic(map[string][]byte{"git-basic.password": []byte("stored-password")}, nil))
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

func TestBearerTokenUsesNetworkSecretAndIdempotencyKey(t *testing.T) {
	manager := NewManager(NewStatic(map[string][]byte{"github-api.token": []byte("stored-token")}, nil))
	req := httptest.NewRequest(http.MethodPost, "https://api.example.test/repos?debug=1", nil)
	req.Header.Set("Authorization", "Bearer guest-token")

	err := manager.Apply(context.Background(), req, &hooks.Credential{Kind: "bearer_token", Name: "github-api", IdempotencyKey: true})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer stored-token" {
		t.Fatalf("expected stored bearer token, got %q", got)
	}
	if req.Header.Get("Idempotency-Key") == "" {
		t.Fatal("expected idempotency key to be generated")
	}
}

func TestHeaderTokenAppliesTokenSlotAndOverwritesManagedHeader(t *testing.T) {
	manager := NewManager(NewStatic(map[string][]byte{"internal-api.token": []byte("stored-token")}, nil))
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

func TestInvalidUTF8SecretFailsClosed(t *testing.T) {
	manager := NewManager(NewStatic(map[string][]byte{"api.token": {0xff}}, nil))
	req := httptest.NewRequest(http.MethodGet, "https://api.example.test", nil)

	err := manager.Apply(context.Background(), req, &hooks.Credential{Kind: "bearer_token", Name: "api"})
	if err == nil || FailureReason(err) != ReasonSecret {
		t.Fatalf("expected invalid slot to fail closed with %q, got %v", ReasonSecret, err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("invalid slot must not inject Authorization, got %q", got)
	}
}

func TestRequiredPlainSlotRejectsEmptyValue(t *testing.T) {
	manager := NewManager(NewStatic(map[string][]byte{"api.token": {}}, nil))
	req := httptest.NewRequest(http.MethodGet, "https://api.example.test", nil)

	err := manager.Apply(context.Background(), req, &hooks.Credential{Kind: "bearer_token", Name: "api"})
	if err == nil || FailureReason(err) != ReasonSecret {
		t.Fatalf("expected empty slot to fail closed with %q, got %v", ReasonSecret, err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("empty slot must not inject Authorization, got %q", got)
	}
}

func TestGitHubOAuthUsesBearerForAPIAndBasicForSmartHTTP(t *testing.T) {
	manager := NewManager(NewStatic(map[string][]byte{"personal.oauth.access_token": []byte("gh-access-token"), "personal.oauth.expires_at": []byte("2026-06-02T12:30:00Z")}, nil))
	manager.now = func() time.Time { return mustTime(t, "2026-06-02T12:00:00Z") }
	credential := &hooks.Credential{Kind: "github_oauth", Name: "personal", Endpoint: "github"}

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

func TestOpenAICodexOAuthInjectsHeadersAndRefreshesExpiredSecretWithHook(t *testing.T) {
	source := NewStatic(map[string][]byte{"personal.oauth.access_token": []byte("old-access-token"), "personal.oauth.expires_at": []byte("2026-06-02T11:59:00Z"), "personal.oauth.account_id": []byte("acct_old")}, configureOAuthRefreshHookHelper(t, "expired"))
	manager := NewManager(source)
	manager.now = func() time.Time { return mustTime(t, "2026-06-02T12:00:00Z") }
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/conversation", nil)
	req.Header.Set("Authorization", "Bearer guest-token")
	req.Header.Set("ChatGPT-Account-Id", "guest-account")

	err := manager.Apply(context.Background(), req, &hooks.Credential{Kind: "openai_codex_oauth", Name: "personal", Endpoint: "chatgpt"})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer new-access-token" {
		t.Fatalf("expected refreshed OpenAI auth header, got %q", got)
	}
	if got := req.Header.Get("ChatGPT-Account-Id"); got != "acct_new" {
		t.Fatalf("expected refreshed account id, got %q", got)
	}
	if token, _ := source.Lookup("personal.oauth.access_token"); string(token) != "new-access-token" {
		t.Fatal("source was not refreshed")
	}
}

func TestExpiredOAuthWithoutHookFailsClosed(t *testing.T) {
	manager := NewManager(NewStatic(map[string][]byte{"personal.oauth.access_token": []byte("old-access-token"), "personal.oauth.expires_at": []byte("2026-06-02T11:59:00Z")}, nil))
	manager.now = func() time.Time { return mustTime(t, "2026-06-02T12:00:00Z") }
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/conversation", nil)

	err := manager.Apply(context.Background(), req, &hooks.Credential{Kind: "openai_codex_oauth", Name: "personal", Endpoint: "chatgpt"})
	if err == nil || FailureReason(err) != ReasonRefresh {
		t.Fatalf("expected expired oauth to fail closed with %q, got %v", ReasonRefresh, err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("expired oauth must not inject Authorization, got %q", got)
	}
}

func TestAWSCredentialSignsWithStaticSlots(t *testing.T) {
	manager := NewManager(NewStatic(map[string][]byte{"prod.access_key_id": []byte("AKIASTATIC"), "prod.secret_access_key": []byte("static-secret"), "prod.session_token": []byte("static-session")}, nil))
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
	manager := NewManager(NewStatic(map[string][]byte{"prod.profile": []byte("production-admin")}, nil))
	manager.now = func() time.Time { return mustTime(t, "2026-06-02T12:00:00Z") }
	path := filepath.Join(t.TempDir(), "credentials")
	if err := os.WriteFile(path, []byte("[production-admin]\naws_access_key_id=AKIAPROFILE\naws_secret_access_key=profile-secret\naws_session_token=profile-session\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", path)
	configPath := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(configPath, []byte("[profile production-admin]\nregion=us-east-1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", configPath)
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_SESSION_TOKEN", "")
	req := httptest.NewRequest(http.MethodGet, "https://dynamodb.us-east-1.amazonaws.com/", nil)

	err := manager.Apply(context.Background(), req, &hooks.Credential{Kind: "aws_credential", Name: "prod"})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
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

func TestOAuthRefreshHookHelperProcess(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--provider-helper" {
		return
	}
	if len(os.Environ()) != 0 {
		t.Fatal("provider environment is not empty")
	}
	mode := os.Args[len(os.Args)-1]
	if mode == "timeout" {
		time.Sleep(time.Minute)
		os.Exit(1)
	}
	if mode == "fail" {
		_, _ = os.Stderr.WriteString("must-not-leak-grant-or-token")
		os.Exit(2)
	}
	var request oauthRefreshHookRequest
	if err := readJSONFrame(os.Stdin, &request); err != nil {
		t.Fatalf("read hook request: %v", err)
	}
	expectedReason := mode
	if mode == "invalid-expiry" || mode == "error" || mode == "expired-response" {
		expectedReason = "expired"
	}
	if request.Version != 1 || request.Grant != base64.StdEncoding.EncodeToString([]byte("opaque-hook-auth")) || request.Operation != "oauth_refresh" || request.Credential.Name != "personal" || request.Credential.Kind != "openai_codex_oauth" || request.Credential.Endpoint != "chatgpt" || request.Reason != expectedReason {
		t.Fatal("unexpected hook request")
	}
	response := oauthRefreshHookResponse{
		Version: 1,
		Status:  "ok",
		OAuth: oauthRefreshHookOAuth{
			AccessToken: "new-access-token",
			ExpiresAt:   "2026-06-02T13:00:00Z",
			AccountID:   "acct_new",
		},
	}
	if mode == "invalid-expiry" {
		response.OAuth.ExpiresAt = "bad-expiry"
	}
	if mode == "expired-response" {
		response.OAuth.ExpiresAt = "2026-06-02T11:00:00Z"
	}
	if mode == "error" {
		response.Status = "error"
		response.Error = oauthRefreshHookErrorBody{Code: "provider_rejected", Message: "must-not-leak-secret"}
	}
	payload, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	if err := writeJSONFrame(os.Stdout, payload); err != nil {
		t.Fatalf("write hook response: %v", err)
	}
	os.Exit(0)
}

func TestOAuthRefreshRejectsBadProviderResponse(t *testing.T) {
	for _, mode := range []string{"invalid-expiry", "expired-response", "error"} {
		t.Run(mode, func(t *testing.T) {
			source := NewStatic(map[string][]byte{"personal.oauth.access_token": []byte("old"), "personal.oauth.expires_at": []byte("2026-06-02T11:59:00Z")}, configureOAuthRefreshHookHelper(t, mode))
			manager := NewManager(source)
			manager.now = func() time.Time { return mustTime(t, "2026-06-02T12:00:00Z") }
			req := httptest.NewRequest(http.MethodGet, "https://chatgpt.com/", nil)
			err := manager.Apply(context.Background(), req, &hooks.Credential{Kind: "openai_codex_oauth", Name: "personal", Endpoint: "chatgpt"})
			if err == nil || req.Header.Get("Authorization") != "" {
				t.Fatal("invalid response did not fail closed")
			}
			if strings.Contains(err.Error(), "must-not-leak") || strings.Contains(err.Error(), "bad-expiry") {
				t.Fatal("provider secret leaked into error")
			}
		})
	}
}

func TestProviderOutputBoundAppliesToIOCopy(t *testing.T) {
	output := boundedOutput{limit: 128}
	if _, err := io.Copy(&output, strings.NewReader(strings.Repeat("x", 129))); err == nil {
		t.Fatal("provider output bound bypassed")
	}
	if len(output.Bytes()) > 128 {
		t.Fatal("provider output exceeded limit")
	}
}

func TestOAuthRefreshFailureFallbackAndExpiredFailClosed(t *testing.T) {
	for _, mode := range []string{"fail", "timeout"} {
		for _, expired := range []bool{false, true} {
			t.Run(mode+map[bool]string{false: "-proactive", true: "-expired"}[expired], func(t *testing.T) {
				provider := configureOAuthRefreshHookHelper(t, mode)
				provider.TimeoutMS = 50
				expiry := "2026-06-02T12:01:00Z"
				if expired {
					expiry = "2026-06-02T11:59:00Z"
				}
				source := NewStatic(map[string][]byte{"personal.oauth.access_token": []byte("old-access-token"), "personal.oauth.expires_at": []byte(expiry)}, provider)
				manager := NewManager(source)
				manager.now = func() time.Time { return mustTime(t, "2026-06-02T12:00:00Z") }
				req := httptest.NewRequest(http.MethodGet, "https://chatgpt.com/", nil)
				err := manager.Apply(context.Background(), req, &hooks.Credential{Kind: "openai_codex_oauth", Name: "personal", Endpoint: "chatgpt"})
				if expired {
					if err == nil || req.Header.Get("Authorization") != "" {
						t.Fatal("expired credential did not fail closed")
					}
				} else if err != nil || req.Header.Get("Authorization") != "Bearer old-access-token" {
					t.Fatalf("lost proactive fallback: %v", err)
				}
				if err != nil && strings.Contains(err.Error(), "must-not-leak") {
					t.Fatal("provider stderr leaked")
				}
			})
		}
	}
}

func TestOAuthRefreshProactiveUsesPolicyMetadata(t *testing.T) {
	source := NewStatic(map[string][]byte{"personal.oauth.access_token": []byte("old"), "personal.oauth.expires_at": []byte("2026-06-02T12:01:00Z")}, configureOAuthRefreshHookHelper(t, "expires_soon"))
	manager := NewManager(source)
	manager.now = func() time.Time { return mustTime(t, "2026-06-02T12:00:00Z") }
	req := httptest.NewRequest(http.MethodGet, "https://chatgpt.com/", nil)
	if err := manager.Apply(context.Background(), req, &hooks.Credential{Kind: "openai_codex_oauth", Name: "personal", Endpoint: "chatgpt"}); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Authorization") != "Bearer new-access-token" {
		t.Fatal("proactive refresh missing")
	}
}

func configureOAuthRefreshHookHelper(t *testing.T, mode string) *Provider {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable returned error: %v", err)
	}
	return &Provider{
		Version:            1,
		Command:            executable,
		Args:               []string{"-test.run=^TestOAuthRefreshHookHelperProcess$", "--", "--provider-helper", mode},
		TimeoutMS:          5000,
		RefreshSkewSeconds: 300,
		Grant:              []byte("opaque-hook-auth"),
	}
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return parsed
}
