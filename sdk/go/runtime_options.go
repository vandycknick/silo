package silo

import "strings"

type runtimeConfig struct {
	Home           string `json:"home,omitempty"`
	RuntimeRoot    string `json:"runtime_root,omitempty"`
	SupervisorPath string `json:"supervisor_path,omitempty"`
}

// RuntimeOption configures [Open].
type RuntimeOption func(*runtimeConfig)

// WithHome selects the Silo home holding all persistent state. It defaults to
// SILO_HOME, else ~/.silo; generated sockets always live under /tmp/silo-<uid>.
func WithHome(path string) RuntimeOption {
	return func(config *runtimeConfig) { config.Home = path }
}

// WithRuntimeRoot selects one complete portable runtime installation.
func WithRuntimeRoot(path string) RuntimeOption {
	return func(config *runtimeConfig) { config.RuntimeRoot = path }
}

// WithSupervisorPath overrides only the silo-vmmon executable path.
func WithSupervisorPath(path string) RuntimeOption {
	return func(config *runtimeConfig) { config.SupervisorPath = path }
}

func (config runtimeConfig) validate() error {
	paths := []struct{ name, value string }{
		{name: "home", value: config.Home},
		{name: "runtime root", value: config.RuntimeRoot},
		{name: "supervisor path", value: config.SupervisorPath},
	}
	for _, path := range paths {
		if path.value != "" && strings.TrimSpace(path.value) == "" {
			return newError(ErrorInvalidArgument, "", path.name+" must not be blank")
		}
	}
	return nil
}
