package credentials

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/vandycknick/silo/net/netd/internal/gateway/hooks"
	"golang.org/x/sys/unix"
)

const MaxSecretsBody = 16384
const maxFrameHeader = 128
const secretsReadTimeout = 10 * time.Second

var ErrNoProvider = errors.New("secret provider is not configured")

type Source interface {
	Lookup(string) ([]byte, bool)
	Refresh(context.Context, []string, string) (map[string][]byte, error)
}

// Provider carries raw grant bytes. The v1 adapter treats them as opaque.
type Provider struct {
	Version            int      `json:"version"`
	Command            string   `json:"command"`
	Args               []string `json:"args"`
	TimeoutMS          int64    `json:"timeout_ms,omitempty"`
	RefreshSkewSeconds int64    `json:"refresh_skew_seconds,omitempty"`
	Grant              []byte   `json:"-"`
}

type Static struct {
	mu       sync.RWMutex
	values   map[string][]byte
	provider *Provider
	bindings map[string]hooks.Credential
}

func NewStatic(values map[string][]byte, provider *Provider) *Static {
	s := &Static{values: make(map[string][]byte), bindings: make(map[string]hooks.Credential)}
	for name, value := range values {
		s.values[name] = bytes.Clone(value)
	}
	if provider != nil {
		copy := *provider
		copy.Args = append([]string{}, provider.Args...)
		copy.Grant = bytes.Clone(provider.Grant)
		s.provider = &copy
	}
	return s
}

func (s *Static) Lookup(name string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.values[name]
	return bytes.Clone(v), ok
}

// BindCredential retains trusted policy metadata for the transport-only v1
// adapter. No credential identity is inferred from the opaque grant.
func (s *Static) BindCredential(credential *hooks.Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bindings[oauthSlotKey(credential.Name)] = *credential
}

func (s *Static) refreshSkew() time.Duration {
	if s.provider == nil || s.provider.RefreshSkewSeconds == 0 {
		return defaultOAuthRefreshSkew
	}
	return time.Duration(s.provider.RefreshSkewSeconds) * time.Second
}

func (s *Static) Refresh(ctx context.Context, names []string, reason string) (map[string][]byte, error) {
	if s.provider == nil {
		return nil, ErrNoProvider
	}
	if err := validateProvider(s.provider); err != nil {
		return nil, err
	}
	if len(names) != 3 {
		return nil, errors.New("v1 refresh requires one OAuth credential")
	}
	key, ok := strings.CutSuffix(names[0], ".access_token")
	if !ok || names[1] != key+".expires_at" || names[2] != key+".account_id" {
		return nil, errors.New("invalid v1 refresh slots")
	}
	s.mu.RLock()
	credential, bound := s.bindings[key]
	expiresAt := string(s.values[key+".expires_at"])
	s.mu.RUnlock()
	if !bound {
		return nil, errors.New("OAuth credential has no policy binding")
	}
	timeout := defaultOAuthRefreshTimeout
	if s.provider.TimeoutMS != 0 {
		timeout = time.Duration(s.provider.TimeoutMS) * time.Millisecond
	}
	hook := &OAuthRefreshHook{command: s.provider.Command, args: s.provider.Args, auth: base64.StdEncoding.EncodeToString(s.provider.Grant), timeout: timeout}
	secret, err := hook.Refresh(ctx, &credential, expiresAt, reason)
	if err != nil {
		return nil, err
	}
	if _, err := time.Parse(time.RFC3339, secret.ExpiresAt); err != nil {
		return nil, errors.New("provider returned invalid OAuth expiry")
	}
	values := map[string][]byte{names[0]: []byte(secret.AccessToken), names[1]: []byte(secret.ExpiresAt), names[2]: []byte(secret.AccountID)}
	s.mu.Lock()
	for name, value := range values {
		s.values[name] = bytes.Clone(value)
	}
	s.mu.Unlock()
	return values, nil
}

func validateProvider(p *Provider) error {
	if p.Version != 1 || !filepath.IsAbs(p.Command) || strings.ContainsRune(p.Command, 0) || p.Args == nil || len(p.Grant) == 0 {
		return errors.New("invalid secret provider configuration")
	}
	for _, arg := range p.Args {
		if strings.ContainsRune(arg, 0) {
			return errors.New("invalid provider argument")
		}
	}
	if p.TimeoutMS < 0 || p.TimeoutMS > math.MaxInt64/int64(time.Millisecond) || p.RefreshSkewSeconds < 0 || p.RefreshSkewSeconds > math.MaxInt64/int64(time.Second) {
		return errors.New("invalid provider timing")
	}
	return nil
}

// LoadFromFD consumes and closes a read-only FIFO in the final worker only.
func LoadFromFD(fd int) (*Static, error) { return loadFromFD(fd, secretsReadTimeout) }

func loadFromFD(fd int, timeout time.Duration) (*Static, error) {
	if fd < 3 {
		return nil, errors.New("secrets descriptor must be above stderr")
	}
	unix.CloseOnExec(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFIFO || flags&unix.O_ACCMODE != unix.O_RDONLY {
		_ = unix.Close(fd)
		return nil, errors.New("secrets descriptor must be a read-only FIFO")
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	// O_NONBLOCK lets Go register the inherited pipe with netpoll for deadlines.
	file := os.NewFile(uintptr(fd), "netd-secrets")
	defer file.Close()
	if err := file.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	payload, err := readFrame(file, MaxSecretsBody)
	if err != nil {
		return nil, fmt.Errorf("read secrets frame: %w", err)
	}
	return decodeSecrets(payload)
}

func decodeSecrets(payload []byte) (*Static, error) {
	var wire struct {
		Version int `json:"version"`
		Secrets *[]struct {
			Name  string  `json:"name"`
			Value *string `json:"value"`
		} `json:"secrets"`
		Provider *struct {
			Version            int      `json:"version"`
			Command            string   `json:"command"`
			Args               []string `json:"args"`
			TimeoutMS          int64    `json:"timeout_ms,omitempty"`
			RefreshSkewSeconds int64    `json:"refresh_skew_seconds,omitempty"`
			Grant              *string  `json:"grant"`
		} `json:"provider,omitempty"`
	}
	if err := decodeJSON(payload, &wire); err != nil {
		return nil, errors.New("invalid secrets JSON")
	}
	if wire.Version != 1 || wire.Secrets == nil {
		return nil, errors.New("secrets version 1 and secrets array are required")
	}
	if err := validateSecretsFields(payload); err != nil {
		return nil, err
	}
	values := make(map[string][]byte)
	for _, entry := range *wire.Secrets {
		if !validSecretName(entry.Name) || entry.Value == nil {
			return nil, errors.New("invalid secret entry")
		}
		if _, exists := values[entry.Name]; exists {
			return nil, errors.New("duplicate secret name")
		}
		value, err := decodeBase64(*entry.Value)
		if err != nil {
			return nil, errors.New("invalid secret base64")
		}
		values[entry.Name] = value
	}
	var provider *Provider
	if p := wire.Provider; p != nil {
		if p.Grant == nil {
			return nil, errors.New("provider grant is required")
		}
		grant, err := decodeBase64(*p.Grant)
		if err != nil {
			return nil, errors.New("invalid provider grant base64")
		}
		provider = &Provider{Version: p.Version, Command: p.Command, Args: p.Args, TimeoutMS: p.TimeoutMS, RefreshSkewSeconds: p.RefreshSkewSeconds, Grant: grant}
		if err := validateProvider(provider); err != nil {
			return nil, err
		}
	}
	return NewStatic(values, provider), nil
}

// encoding/json matches struct fields case-insensitively. The wire contract
// uses exact names, so reject case aliases as well as unknown fields.
func validateSecretsFields(payload []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(payload, &root); err != nil {
		return errors.New("invalid secrets object")
	}
	if !exactFields(root, "version", "secrets", "provider") {
		return errors.New("unknown secrets field")
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(root["secrets"], &entries); err != nil {
		return errors.New("invalid secrets entries")
	}
	for _, entry := range entries {
		if !exactFields(entry, "name", "value") {
			return errors.New("unknown secret entry field")
		}
	}
	if raw, ok := root["provider"]; ok {
		var provider map[string]json.RawMessage
		if err := json.Unmarshal(raw, &provider); err != nil {
			return errors.New("invalid provider object")
		}
		if !exactFields(provider, "version", "command", "args", "timeout_ms", "refresh_skew_seconds", "grant") {
			return errors.New("unknown provider field")
		}
	}
	return nil
}

func exactFields(fields map[string]json.RawMessage, allowed ...string) bool {
	for field := range fields {
		found := false
		for _, name := range allowed {
			if field == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func validSecretName(name string) bool {
	if name == "" || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r)) {
			return false
		}
	}
	return true
}

func decodeBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("noncanonical base64")
	}
	return decoded, nil
}

func readFrame(reader io.Reader, maxBody int) ([]byte, error) {
	buffered := bufio.NewReaderSize(reader, maxFrameHeader)
	header := make([]byte, 0, maxFrameHeader)
	for !bytes.HasSuffix(header, []byte("\r\n\r\n")) {
		if len(header) == maxFrameHeader {
			return nil, errors.New("frame header too large")
		}
		b, err := buffered.ReadByte()
		if err != nil {
			return nil, err
		}
		header = append(header, b)
	}
	text := string(header)
	if !strings.HasPrefix(text, "Content-Length: ") {
		return nil, errors.New("invalid frame header")
	}
	digits := strings.TrimSuffix(strings.TrimPrefix(text, "Content-Length: "), "\r\n\r\n")
	if digits == "" {
		return nil, errors.New("missing frame length")
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return nil, errors.New("invalid frame length")
		}
	}
	length, err := strconv.Atoi(digits)
	if err != nil || length > maxBody {
		return nil, errors.New("frame body too large")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(buffered, payload); err != nil {
		return nil, err
	}
	if _, err := buffered.ReadByte(); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("trailing frame bytes")
	}
	return payload, nil
}

func decodeJSON(payload []byte, target any) error {
	if !utf8.Valid(payload) {
		return errors.New("invalid JSON encoding")
	}
	shape := json.NewDecoder(bytes.NewReader(payload))
	if err := validateJSONValue(shape); err != nil {
		return err
	}
	if _, err := shape.Token(); err != io.EOF {
		return errors.New("trailing JSON values")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON values")
	}
	return nil
}

func validateJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return errors.New("null JSON field")
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate JSON field")
			}
			seen[name] = true
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}
