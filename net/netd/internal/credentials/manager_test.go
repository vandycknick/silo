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
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/vandycknick/bentobox/net/netd/internal/gateway/hooks"
)

func TestBasicAuthAppliesPasswordSlotAndOverwritesAuthorization(t *testing.T) {
	setNetworkSecret(t, "git-basic.password", "stored-password")
	manager := NewManager()
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
	setNetworkSecret(t, "github-api.token", "env-token")
	manager := NewManager()
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
	setNetworkSecret(t, "internal-api.token", "stored-token")
	manager := NewManager()
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

func TestInvalidBase64SecretFailsClosed(t *testing.T) {
	t.Setenv(envNameForSlot("api.token"), "not base64!!!")
	manager := NewManager()
	req := httptest.NewRequest(http.MethodGet, "https://api.example.test", nil)

	err := manager.Apply(context.Background(), req, &hooks.Credential{Kind: "bearer_token", Name: "api"})
	if err == nil || FailureReason(err) != ReasonSecret {
		t.Fatalf("expected invalid env slot to fail closed with %q, got %v", ReasonSecret, err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("invalid env slot must not inject Authorization, got %q", got)
	}
}

func TestRequiredPlainSlotRejectsEmptyValue(t *testing.T) {
	t.Setenv(envNameForSlot("api.token"), "")
	manager := NewManager()
	req := httptest.NewRequest(http.MethodGet, "https://api.example.test", nil)

	err := manager.Apply(context.Background(), req, &hooks.Credential{Kind: "bearer_token", Name: "api"})
	if err == nil || FailureReason(err) != ReasonSecret {
		t.Fatalf("expected empty env slot to fail closed with %q, got %v", ReasonSecret, err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("empty env slot must not inject Authorization, got %q", got)
	}
}

func TestGitHubOAuthUsesBearerForAPIAndBasicForSmartHTTP(t *testing.T) {
	setNetworkSecret(t, "personal.oauth.access_token", "gh-access-token")
	setNetworkSecret(t, "personal.oauth.expires_at", "2026-06-02T12:30:00Z")
	manager := NewManager()
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
	setNetworkSecret(t, "personal.oauth.access_token", "old-access-token")
	setNetworkSecret(t, "personal.oauth.expires_at", "2026-06-02T11:59:00Z")
	setNetworkSecret(t, "personal.oauth.account_id", "acct_old")
	configureOAuthRefreshHookHelper(t)
	manager, err := NewManagerFromEnvironment()
	if err != nil {
		t.Fatalf("NewManagerFromEnvironment returned error: %v", err)
	}
	manager.now = func() time.Time { return mustTime(t, "2026-06-02T12:00:00Z") }
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/conversation", nil)
	req.Header.Set("Authorization", "Bearer guest-token")
	req.Header.Set("ChatGPT-Account-Id", "guest-account")

	err = manager.Apply(context.Background(), req, &hooks.Credential{Kind: "openai_codex_oauth", Name: "personal", Endpoint: "chatgpt"})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer new-access-token" {
		t.Fatalf("expected refreshed OpenAI auth header, got %q", got)
	}
	if got := req.Header.Get("ChatGPT-Account-Id"); got != "acct_new" {
		t.Fatalf("expected refreshed account id, got %q", got)
	}
}

func TestExpiredOAuthWithoutHookFailsClosed(t *testing.T) {
	setNetworkSecret(t, "personal.oauth.access_token", "old-access-token")
	setNetworkSecret(t, "personal.oauth.expires_at", "2026-06-02T11:59:00Z")
	manager := NewManager()
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
	setNetworkSecret(t, "prod.access_key_id", "AKIASTATIC")
	setNetworkSecret(t, "prod.secret_access_key", "static-secret")
	setNetworkSecret(t, "prod.session_token", "static-session")
	manager := NewManager()
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
	setNetworkSecret(t, "prod.profile", "production-admin")
	manager := NewManager()
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

func TestOAuthRefreshHookHelperProcess(t *testing.T) {
	if os.Getenv(OAuthRefreshAuthEnv) == "" {
		return
	}
	if os.Getenv(OAuthRefreshAuthEnv) != base64.StdEncoding.EncodeToString([]byte("hook-auth")) {
		t.Fatalf("hook did not receive expected auth env")
	}
	if os.Getenv(envNameForSlot("personal.oauth.access_token")) != "" {
		t.Fatalf("hook received network secret env")
	}
	var request oauthRefreshHookRequest
	if err := readJSONFrame(os.Stdin, &request); err != nil {
		t.Fatalf("read hook request: %v", err)
	}
	if request.Operation != "oauth_refresh" || request.Credential.Name != "personal" || request.Credential.Kind != "openai_codex_oauth" || request.Credential.Endpoint != "chatgpt" || request.Reason != "expired" {
		t.Fatalf("unexpected hook request: %#v", request)
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
	payload, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	if err := writeJSONFrame(os.Stdout, payload); err != nil {
		t.Fatalf("write hook response: %v", err)
	}
	os.Exit(0)
}

func configureOAuthRefreshHookHelper(t *testing.T) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable returned error: %v", err)
	}
	config := oauthRefreshHookConfig{
		Version:            1,
		Command:            executable,
		Args:               []string{"-test.run=TestOAuthRefreshHookHelperProcess"},
		TimeoutMS:          5000,
		RefreshSkewSeconds: 300,
	}
	payload, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal hook config: %v", err)
	}
	t.Setenv(OAuthRefreshHookEnv, base64.StdEncoding.EncodeToString(payload))
	t.Setenv(OAuthRefreshAuthEnv, base64.StdEncoding.EncodeToString([]byte("hook-auth")))
}

func setNetworkSecret(t *testing.T, slot string, value string) {
	t.Helper()
	t.Setenv(envNameForSlot(slot), base64.StdEncoding.EncodeToString([]byte(value)))
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return parsed
}
