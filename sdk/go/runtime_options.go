package silo

import (
	"path/filepath"
	"strings"
)

type runtimeConfig struct {
	Home                string             `json:"home,omitempty"`
	RuntimeRoot         string             `json:"runtime_root,omitempty"`
	SupervisorPath      string             `json:"supervisor_path,omitempty"`
	RuntimeComponents   *RuntimeComponents `json:"runtime_components,omitempty"`
	runtimeRootSelected bool
	supervisorSelected  bool
}

// RuntimeComponents selects the exact six native components supplied by a
// manager. All paths must be absolute and refer to existing validated assets.
type RuntimeComponents struct {
	SupervisorPath string `json:"supervisor_path"`
	NetdPath       string `json:"netd_path"`
	KernelPath     string `json:"kernel_path"`
	InitramfsPath  string `json:"initramfs_path"`
	AgentPath      string `json:"agent_path"`
	AssetDir       string `json:"asset_dir"`
}

// WithRuntimeComponents pins an exact native component set, bypassing ambient
// discovery. It cannot be combined with WithRuntimeRoot or WithSupervisorPath,
// even if either selector is passed an empty path.
func WithRuntimeComponents(value RuntimeComponents) RuntimeOption {
	return func(config *runtimeConfig) { config.RuntimeComponents = &value }
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
	return func(config *runtimeConfig) {
		config.RuntimeRoot = path
		config.runtimeRootSelected = true
	}
}

// WithSupervisorPath overrides only the silo-vmm executable path.
func WithSupervisorPath(path string) RuntimeOption {
	return func(config *runtimeConfig) {
		config.SupervisorPath = path
		config.supervisorSelected = true
	}
}

func (config runtimeConfig) validate() error {
	if config.RuntimeComponents != nil {
		if config.runtimeRootSelected || config.supervisorSelected || config.RuntimeRoot != "" || config.SupervisorPath != "" {
			return newError(ErrorInvalidArgument, "", "runtime components conflict with runtime root or supervisor path")
		}
		for _, path := range []struct{ name, value string }{
			{"supervisor path", config.RuntimeComponents.SupervisorPath},
			{"netd path", config.RuntimeComponents.NetdPath},
			{"kernel path", config.RuntimeComponents.KernelPath},
			{"initramfs path", config.RuntimeComponents.InitramfsPath},
			{"agent path", config.RuntimeComponents.AgentPath},
			{"asset directory", config.RuntimeComponents.AssetDir},
		} {
			if strings.TrimSpace(path.value) == "" {
				return newError(ErrorInvalidArgument, "", "runtime components "+path.name+" must not be blank")
			}
			if !filepath.IsAbs(path.value) {
				return newError(ErrorInvalidArgument, "", "runtime components "+path.name+" must be absolute")
			}
		}
	}
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
