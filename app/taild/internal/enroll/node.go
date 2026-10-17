package enroll

import (
	"context"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/metrics"
	"github.com/vandycknick/silo/app/taild/internal/state"
)

// Manager obtains bootstrap consent and carries the lobby's pinned identity.
// The VM's netd exclusively owns node registration and authentication state.
type Manager struct {
	Metrics  *metrics.Metrics
	Config   config.Config
	Secrets  config.Secrets
	Pin      state.NodePin
	Registry *Registry
	OAuth    *OAuth
}

// Mode picks how a VM owned by owner bootstraps its node: tags use the client
// secret, humans use a one-shot OAuth key when an app secret exists, otherwise
// they log in interactively.
func (m *Manager) Mode(owner identity.Principal) Mode {
	switch {
	case m.Config.Enrollment.Mode == "none":
		return None
	case owner.IsTag():
		return Tag
	case m.Config.Enrollment.Mode != "interactive" && m.Secrets.AppSecret != "":
		return User
	}
	return Interactive
}

// Acquire binds consent to a reserved creation attempt, before a VM ID exists.
// The caller stores the returned bootstrap key only after creating the VM scope.
func (m *Manager) Acquire(ctx context.Context, attempt string, owner identity.Principal, progress func(string)) (key []byte, result error) {
	if m.Mode(owner) != User {
		return nil, nil
	}
	started := time.Now()
	defer func() { m.Metrics.Latency("enrollment", time.Since(started), result == nil) }()
	if m.OAuth == nil || m.Registry == nil {
		return nil, &authz.Error{Code: "unavailable", Message: "configured OAuth app unavailable", Exit: 9}
	}
	nonce, consent, err := m.Registry.Begin(attempt, owner, m.OAuth.ClientID, m.OAuth.Redirect)
	if err != nil {
		return nil, &authz.Error{Code: "unavailable", Message: "consent unavailable", Exit: 9}
	}
	defer m.Registry.Cancel(nonce)
	progress("approve: " + consent.URL)
	token, err := consent.Wait(ctx)
	if err != nil {
		return nil, &authz.Error{Code: "pending_approval", Message: "consent denied, expired or interrupted; no VM was created", Exit: 8}
	}
	return []byte(token), nil
}
