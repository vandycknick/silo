package credentials

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
	"unicode/utf8"
)

const defaultOAuthRefreshTimeout = 10 * time.Second
const defaultOAuthRefreshSkew = 5 * time.Minute

type requestScope struct {
	Machine string `json:"machine"`
	Run     string `json:"run"`
}
type providerRequest struct {
	Version   int          `json:"version"`
	Operation string       `json:"operation"`
	Grant     string       `json:"grant"`
	Scope     requestScope `json:"scope"`
	Names     []string     `json:"names"`
	Reason    string       `json:"reason"`
}
type providerSecret struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type providerResponse struct {
	Version int               `json:"version"`
	Status  string            `json:"status"`
	Secrets *[]providerSecret `json:"secrets,omitempty"`
	Error   *providerError    `json:"error,omitempty"`
}
type providerError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

func (p *Provider) get(ctx context.Context, names []string, reason string) (map[string][]byte, error) {
	// netd extracts only run identity and allowed slot names, never backing records.
	var grant struct {
		Machine string `json:"machine"`
		Run     string `json:"run"`
		Allowed []struct {
			Slot string `json:"slot"`
		} `json:"allowed"`
	}
	if err := json.Unmarshal(p.Grant, &grant); err != nil || len(grant.Machine) != 32 || grant.Run == "" {
		return nil, errors.New("invalid provider grant scope")
	}
	for _, c := range grant.Machine {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, errors.New("invalid provider machine")
		}
	}
	allowed := make(map[string]bool)
	for _, entry := range grant.Allowed {
		allowed[entry.Slot] = true
	}
	requested := make(map[string]bool)
	for _, name := range names {
		if !validSecretName(name) || strings.HasPrefix(name, "silo.") || requested[name] || !allowed[name] {
			return nil, errors.New("provider name is not granted")
		}
		requested[name] = true
	}
	if len(names) == 0 {
		return nil, errors.New("empty provider request")
	}
	timeout := defaultOAuthRefreshTimeout
	if p.TimeoutMS != 0 {
		timeout = time.Duration(p.TimeoutMS) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	payload, err := json.Marshal(providerRequest{2, "get", base64.StdEncoding.EncodeToString(p.Grant), requestScope{grant.Machine, grant.Run}, names, reason})
	if err != nil {
		return nil, err
	}
	var input bytes.Buffer
	if err := writeJSONFrame(&input, payload); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, p.Command, p.Args...)
	cmd.Env = []string{}
	cmd.WaitDelay = time.Second
	cmd.Stdin = &input
	stdout := boundedOutput{limit: (1 << 20) + maxFrameHeader}
	cmd.Stdout = &stdout
	cmd.Stderr = io.Discard
	err = cmd.Run()
	if ctx.Err() != nil {
		return nil, errors.New("secret provider timed out or canceled")
	}
	if err != nil {
		return nil, fmt.Errorf("secret provider failed: %w", err)
	}
	var response providerResponse
	if err := readJSONFrame(bytes.NewReader(stdout.Bytes()), &response); err != nil {
		return nil, errors.New("invalid provider response")
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(stdoutBody(stdout.Bytes()), &root); err != nil || !exactFields(root, "version", "status", "secrets", "error") {
		return nil, errors.New("invalid provider response fields")
	}
	if raw, ok := root["secrets"]; ok {
		var entries []map[string]json.RawMessage
		if json.Unmarshal(raw, &entries) != nil {
			return nil, errors.New("invalid provider secrets")
		}
		for _, entry := range entries {
			if !exactFields(entry, "name", "value") || len(entry) != 2 {
				return nil, errors.New("invalid provider secret fields")
			}
		}
	}
	if raw, ok := root["error"]; ok {
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || !exactFields(fields, "code", "message", "retryable") || len(fields) != 3 {
			return nil, errors.New("invalid provider error fields")
		}
	}
	if response.Version != 2 {
		return nil, errors.New("unsupported provider response version")
	}
	if response.Status == "error" {
		if response.Secrets != nil || response.Error == nil || !validProviderErrorCode(response.Error.Code) {
			return nil, errors.New("invalid provider error")
		}
		return nil, fmt.Errorf("secret provider returned %s", response.Error.Code)
	}
	if response.Status != "ok" || response.Error != nil || response.Secrets == nil {
		return nil, errors.New("invalid provider status")
	}
	values := make(map[string][]byte)
	for _, entry := range *response.Secrets {
		if !requested[entry.Name] {
			return nil, errors.New("unrequested provider name")
		}
		if _, exists := values[entry.Name]; exists {
			return nil, errors.New("duplicate provider name")
		}
		value, err := decodeBase64(entry.Value)
		if err != nil || len(value) == 0 || !utf8.Valid(value) {
			return nil, errors.New("invalid provider value")
		}
		if strings.HasSuffix(entry.Name, ".oauth.expires_at") {
			if expiry, err := time.Parse(time.RFC3339, string(value)); err != nil || !time.Now().Before(expiry) {
				return nil, errors.New("invalid or expired provider expiry")
			}
		}
		values[entry.Name] = value
	}
	if len(values) != len(requested) {
		return nil, errors.New("missing provider names")
	}
	return values, nil
}

func stdoutBody(frame []byte) []byte { _, body, _ := bytes.Cut(frame, []byte("\r\n\r\n")); return body }
func validProviderErrorCode(code string) bool {
	switch code {
	case "unauthorized", "not_found", "read_only", "unsupported", "provider_unavailable", "provider_rejected", "rate_limited", "invalid_request", "internal_error":
		return true
	}
	return false
}
func writeJSONFrame(writer io.Writer, payload []byte) error {
	if len(payload) > 1<<20 {
		return errors.New("provider input too large")
	}
	if _, err := fmt.Fprintf(writer, "Content-Length: %d\r\n\r\n", len(payload)); err != nil {
		return err
	}
	n, err := writer.Write(payload)
	if err == nil && n != len(payload) {
		return io.ErrShortWrite
	}
	return err
}
func readJSONFrame(reader io.Reader, target any) error {
	payload, err := readFrame(reader, 1<<20)
	if err != nil {
		return err
	}
	return decodeJSON(payload, target)
}

type boundedOutput struct {
	buffer bytes.Buffer
	limit  int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buffer.Len() {
		return 0, errors.New("provider output too large")
	}
	return b.buffer.Write(p)
}
func (b *boundedOutput) Bytes() []byte { return b.buffer.Bytes() }
