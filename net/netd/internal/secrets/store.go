package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var ErrNotFound = errors.New("secret not found")

const (
	TypePlain = "plain"
	TypeOAuth = "oauth"

	storeFileSizeLimit = 1 << 20
)

type Store interface {
	Get(name string) (Secret, error)
	UpdateOAuth(name string, secret OAuthSecret) error
}

type Secret struct {
	Type         string `json:"type"`
	Value        string `json:"value,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
	UpdatedAt    string `json:"updated_at,omitempty"`
}

type OAuthSecret struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    string
	AccountID    string
	CreatedAt    string
	UpdatedAt    string
}

func Plain(value string) Secret {
	return Secret{Type: TypePlain, Value: value}
}

func OAuth(secret OAuthSecret) Secret {
	return Secret{
		Type:         TypeOAuth,
		AccessToken:  secret.AccessToken,
		RefreshToken: secret.RefreshToken,
		ExpiresAt:    secret.ExpiresAt,
		AccountID:    secret.AccountID,
		CreatedAt:    secret.CreatedAt,
		UpdatedAt:    secret.UpdatedAt,
	}
}

func (s Secret) PlainValue() (string, error) {
	if s.Type != TypePlain {
		return "", fmt.Errorf("secret has type %q, expected %q", s.Type, TypePlain)
	}
	if s.Value == "" {
		return "", fmt.Errorf("plain secret is missing value")
	}
	return s.Value, nil
}

func (s Secret) OAuth() (OAuthSecret, error) {
	if s.Type != TypeOAuth {
		return OAuthSecret{}, fmt.Errorf("secret has type %q, expected %q", s.Type, TypeOAuth)
	}
	secret := OAuthSecret{
		AccessToken:  s.AccessToken,
		RefreshToken: s.RefreshToken,
		ExpiresAt:    s.ExpiresAt,
		AccountID:    s.AccountID,
		CreatedAt:    s.CreatedAt,
		UpdatedAt:    s.UpdatedAt,
	}
	if err := validateOAuthSecret(secret); err != nil {
		return OAuthSecret{}, err
	}
	return secret, nil
}

type FileStore struct {
	path string
	mu   sync.Mutex
}

func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

func (s *FileStore) Get(name string) (Secret, error) {
	if err := validateName(name); err != nil {
		return Secret{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	secrets, err := s.readAll()
	if err != nil {
		return Secret{}, err
	}
	secret, ok := secrets[name]
	if !ok {
		return Secret{}, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	return secret, nil
}

func (s *FileStore) UpdateOAuth(name string, secret OAuthSecret) error {
	if err := validateName(name); err != nil {
		return err
	}
	if err := validateOAuthSecret(secret); err != nil {
		return fmt.Errorf("validate oauth secret %q: %w", name, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	secrets, err := s.readAll()
	if err != nil {
		return err
	}
	existing, ok := secrets[name]
	if !ok {
		return fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	if existing.Type != TypeOAuth {
		return fmt.Errorf("secret %q has type %q, expected %q", name, existing.Type, TypeOAuth)
	}
	secrets[name] = OAuth(secret)
	return s.writeAll(secrets)
}

func (s *FileStore) readAll() (map[string]Secret, error) {
	if s.path == "" {
		return nil, fmt.Errorf("secret store path is empty")
	}
	f, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return make(map[string]Secret), nil
	}
	if err != nil {
		return nil, fmt.Errorf("open secret store %s: %w", s.path, err)
	}
	defer f.Close()
	var secrets map[string]Secret
	decoder := json.NewDecoder(io.LimitReader(f, storeFileSizeLimit))
	if err := decoder.Decode(&secrets); err != nil {
		return nil, fmt.Errorf("decode secret store %s: %w", s.path, err)
	}
	if secrets == nil {
		secrets = make(map[string]Secret)
	}
	for name, secret := range secrets {
		if err := validateName(name); err != nil {
			return nil, fmt.Errorf("secret %q: %w", name, err)
		}
		if err := validateSecret(secret); err != nil {
			return nil, fmt.Errorf("secret %q: %w", name, err)
		}
	}
	return secrets, nil
}

func (s *FileStore) writeAll(secrets map[string]Secret) error {
	body, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		return fmt.Errorf("encode secret store %s: %w", s.path, err)
	}
	body = append(body, '\n')
	dir := filepath.Dir(s.path)
	base := filepath.Base(s.path)
	tmpPath := filepath.Join(dir, fmt.Sprintf(".%s.tmp.%d", base, os.Getpid()))
	if err := os.WriteFile(tmpPath, body, 0o600); err != nil {
		return fmt.Errorf("write secret store temp file %s: %w", tmpPath, err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("secure secret store temp file %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace secret store %s: %w", s.path, err)
	}
	if err := os.Chmod(s.path, 0o600); err != nil {
		return fmt.Errorf("secure secret store %s: %w", s.path, err)
	}
	return nil
}

func validateSecret(secret Secret) error {
	switch secret.Type {
	case TypePlain:
		if secret.Value == "" {
			return fmt.Errorf("plain secret is missing value")
		}
	case TypeOAuth:
		_, err := secret.OAuth()
		return err
	default:
		return fmt.Errorf("unsupported secret type %q", secret.Type)
	}
	return nil
}

func validateOAuthSecret(secret OAuthSecret) error {
	if secret.AccessToken == "" {
		return fmt.Errorf("oauth secret is missing access_token")
	}
	if secret.RefreshToken == "" {
		return fmt.Errorf("oauth secret is missing refresh_token")
	}
	if secret.ExpiresAt == "" {
		return fmt.Errorf("oauth secret is missing expires_at")
	}
	return nil
}

func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("secret name cannot be empty")
	}
	if name == "." || name == ".." || strings.HasPrefix(name, ".") {
		return fmt.Errorf("secret name %q is not allowed", name)
	}
	for _, ch := range name {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.' {
			continue
		}
		return fmt.Errorf("secret name %q may only contain ASCII letters, numbers, dots, underscores, and dashes", name)
	}
	return nil
}
