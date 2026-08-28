package silo

import "strings"

type runtimeConfig struct {
	DataRoot    string `json:"data_root,omitempty"`
	RunRoot     string `json:"run_root,omitempty"`
	ImageRoot   string `json:"image_root,omitempty"`
	RuntimeRoot string `json:"runtime_root,omitempty"`
	VMMonPath   string `json:"vmmon_path,omitempty"`
}

// RuntimeOption configures [Open].
type RuntimeOption func(*runtimeConfig)

// WithDataRoot selects the persistent Silo data root.
func WithDataRoot(path string) RuntimeOption {
	return func(config *runtimeConfig) { config.DataRoot = path }
}

// WithRunRoot selects the ephemeral socket and process-state root.
func WithRunRoot(path string) RuntimeOption {
	return func(config *runtimeConfig) { config.RunRoot = path }
}

// WithImageRoot selects the OCI image cache root.
func WithImageRoot(path string) RuntimeOption {
	return func(config *runtimeConfig) { config.ImageRoot = path }
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
		{name: "data root", value: config.DataRoot},
		{name: "run root", value: config.RunRoot},
		{name: "image root", value: config.ImageRoot},
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
