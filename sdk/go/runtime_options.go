package silo

import "strings"

type runtimeConfig struct {
	Home        string `json:"home,omitempty"`
	RuntimeRoot string `json:"runtime_root,omitempty"`
	VMMonPath   string `json:"vmmon_path,omitempty"`
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

// WithVMMonPath overrides only the vmmon executable path.
func WithVMMonPath(path string) RuntimeOption {
	return func(config *runtimeConfig) { config.VMMonPath = path }
}

func (config runtimeConfig) validate() error {
	paths := []struct{ name, value string }{
		{name: "home", value: config.Home},
		{name: "runtime root", value: config.RuntimeRoot},
		{name: "vmmon path", value: config.VMMonPath},
	}
	for _, path := range paths {
		if path.value != "" && strings.TrimSpace(path.value) == "" {
			return newError(ErrorInvalidArgument, "", path.name+" must not be blank")
		}
	}
	return nil
}
