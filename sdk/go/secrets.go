package silo

import (
	"context"
	"encoding/json"
)

// SetSecret stores a plain credential in this machine's scope through the
// runtime's secret store. It never writes credentials into machine configuration.
// Existing running helpers retain their launch-time credential snapshot.
func (m *Machine) SetSecret(ctx context.Context, name string, value []byte) error {
	if value == nil {
		value = []byte{}
	}
	return m.secret(ctx, struct {
		Operation string `json:"operation"`
		Name      string `json:"name"`
		Value     []byte `json:"value"`
	}{"set", name, value})
}

// DeleteSecret removes a credential from this machine's scope. Missing keys
// succeed. Reserved silo.* infrastructure credentials cannot be changed here.
func (m *Machine) DeleteSecret(ctx context.Context, name string) error {
	return m.secret(ctx, struct {
		Operation string `json:"operation"`
		Name      string `json:"name"`
	}{"delete", name})
}

func (m *Machine) secret(ctx context.Context, request any) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	if m == nil {
		return newError(ErrorClosed, "", "machine is closed")
	}
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	if m.closed {
		return newError(ErrorClosed, "", "machine is closed")
	}
	b, err := json.Marshal(request)
	if err != nil {
		return err
	}
	defer clear(b)
	return fromNativeError(m.native.Secret(b))
}
