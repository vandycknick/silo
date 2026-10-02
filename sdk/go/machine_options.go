package silo

import (
	"maps"
	"strconv"
	"strings"
)

type imageSourceConfig struct {
	Kind      string `json:"kind"`
	Reference string `json:"reference,omitempty"`
	Path      string `json:"path,omitempty"`
}

// ImageSource is an explicit OCI reference or local disk path.
type ImageSource struct{ config imageSourceConfig }

// OCIImage constructs an OCI image source.
func OCIImage(reference string) ImageSource {
	return ImageSource{config: imageSourceConfig{Kind: "oci", Reference: reference}}
}

// DiskImage constructs a caller-owned local disk image source.
func DiskImage(path string) ImageSource {
	return ImageSource{config: imageSourceConfig{Kind: "disk", Path: path}}
}

// Mount describes an additional host disk mounted into a guest.
type Mount struct {
	Source   string `json:"source"`
	Tag      string `json:"tag"`
	ReadOnly bool   `json:"read_only"`
}

type machineConfig struct {
	Source               imageSourceConfig   `json:"source"`
	Name                 *string             `json:"name,omitempty"`
	Labels               map[string]string   `json:"labels"`
	Metadata             map[string]string   `json:"metadata"`
	CPUs                 *uint8              `json:"cpus,omitempty"`
	MemoryBytes          *uint64             `json:"memory_bytes,omitempty"`
	Kernel               *string             `json:"kernel,omitempty"`
	Initramfs            *string             `json:"initramfs,omitempty"`
	AgentSet             bool                `json:"agent_set"`
	AgentPath            *string             `json:"agent_path,omitempty"`
	RootDiskSizeBytes    *uint64             `json:"root_disk_size_bytes,omitempty"`
	NestedVirtualization *bool               `json:"nested_virtualization,omitempty"`
	Rosetta              *bool               `json:"rosetta,omitempty"`
	Userdata             *string             `json:"userdata,omitempty"`
	Disks                []string            `json:"disks,omitempty"`
	Mounts               []Mount             `json:"mounts,omitempty"`
	Forwards             []Forward           `json:"forwards,omitempty"`
	Vsock                *bool               `json:"vsock,omitempty"`
	Network              *machineNetworkWire `json:"network,omitempty"`
	GuestUser            *GuestUser          `json:"guest_user,omitempty"`
	error                error
}

// MachineOption configures machine creation.
type MachineOption func(*machineConfig)

// GuestUser is the concrete account provisioned by the managed guest agent.
type GuestUser struct {
	Name string `json:"name"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
	Home string `json:"home"`
}

// Validate checks the managed account constraints before image admission.
// Home is a path inside the VM, never a host path.
func (u GuestUser) Validate() error {
	invalid := func(message string) error { return newError(ErrorInvalidArgument, "", message) }
	if u.Name == "root" || u.Name == "nobody" || u.UID == 0 || u.UID == 65534 || u.GID == 0 || u.GID == 65534 {
		return invalid("guest user must not use root or nobody identities")
	}
	if u.UID == ^uint32(0) || u.GID == ^uint32(0) {
		return invalid("guest UID and GID must not use the reserved maximum value")
	}
	body := strings.TrimSuffix(u.Name, "$")
	if len(u.Name) > 256 || body == "" || strings.HasPrefix(body, "-") {
		return invalid("invalid guest user name")
	}
	numeric := true
	for _, c := range body {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return invalid("invalid guest user name")
		}
		numeric = numeric && c >= '0' && c <= '9'
	}
	if numeric && body == u.Name {
		return invalid("invalid guest user name")
	}
	if !strings.HasPrefix(u.Home, "/") || u.Home == "/" || strings.ContainsAny(u.Home, "\x00\n\r:") {
		return invalid("guest user home must be an absolute normalized guest path other than /")
	}
	for _, part := range strings.Split(u.Home, "/") {
		if part == "." || part == ".." {
			return invalid("guest user home must be an absolute normalized guest path")
		}
	}
	return nil
}

// ParseGuestUser parses the explicit NAME:UID:GID:HOME provisioning syntax.
func ParseGuestUser(value string) (GuestUser, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 4 {
		return GuestUser{}, newError(ErrorInvalidArgument, "", "provision user requires NAME:UID:GID:HOME")
	}
	uid, ue := strconv.ParseUint(parts[1], 10, 32)
	gid, ge := strconv.ParseUint(parts[2], 10, 32)
	if ue != nil || ge != nil {
		return GuestUser{}, newError(ErrorInvalidArgument, "", "guest UID and GID must be unsigned 32-bit decimal integers")
	}
	u := GuestUser{Name: parts[0], UID: uint32(uid), GID: uint32(gid), Home: parts[3]}
	return u, u.Validate()
}

// WithGuestUser opts into provisioning a nonroot VM account. Without this option,
// no account is provisioned and sessions default to root.
func WithGuestUser(name string, uid, gid uint32, home string) MachineOption {
	return func(config *machineConfig) {
		u := GuestUser{Name: name, UID: uid, GID: gid, Home: home}
		if err := u.Validate(); err != nil {
			config.error = err
			return
		}
		config.GuestUser = &u
	}
}

func WithName(name string) MachineOption { return func(config *machineConfig) { config.Name = &name } }
func WithLabel(key, value string) MachineOption {
	return func(config *machineConfig) {
		if config.Labels == nil {
			config.Labels = make(map[string]string)
		}
		config.Labels[key] = value
	}
}
func WithLabels(labels map[string]string) MachineOption {
	return func(config *machineConfig) {
		config.Labels = maps.Clone(labels)
		if config.Labels == nil {
			config.Labels = make(map[string]string)
		}
	}
}
func WithMetadataEntry(key, value string) MachineOption {
	return func(config *machineConfig) {
		if config.Metadata == nil {
			config.Metadata = make(map[string]string)
		}
		config.Metadata[key] = value
	}
}
func WithMetadata(metadata map[string]string) MachineOption {
	return func(config *machineConfig) {
		config.Metadata = maps.Clone(metadata)
		if config.Metadata == nil {
			config.Metadata = make(map[string]string)
		}
	}
}
func WithCPUs(cpus uint8) MachineOption { return func(config *machineConfig) { config.CPUs = &cpus } }
func WithMemory(size ByteSize) MachineOption {
	return func(config *machineConfig) {
		if err := size.validate("memory"); err != nil {
			config.error = err
			return
		}
		value := size.Bytes()
		config.MemoryBytes = &value
	}
}
func WithKernel(path string) MachineOption {
	return func(config *machineConfig) { config.Kernel = &path }
}
func WithInitramfs(path string) MachineOption {
	return func(config *machineConfig) { config.Initramfs = &path }
}
func WithGuestAgent(path string) MachineOption {
	return func(config *machineConfig) { config.AgentSet = true; config.AgentPath = &path }
}
func WithoutGuestAgent() MachineOption {
	return func(config *machineConfig) { config.AgentSet = true; config.AgentPath = nil }
}
func WithRootDiskSize(size ByteSize) MachineOption {
	return func(config *machineConfig) {
		if err := size.validate("root disk size"); err != nil {
			config.error = err
			return
		}
		value := size.Bytes()
		config.RootDiskSizeBytes = &value
	}
}
func WithNestedVirtualization(enabled bool) MachineOption {
	return func(config *machineConfig) { config.NestedVirtualization = &enabled }
}
func WithRosetta(enabled bool) MachineOption {
	return func(config *machineConfig) { config.Rosetta = &enabled }
}
func WithUserdata(userdata string) MachineOption {
	return func(config *machineConfig) { config.Userdata = &userdata }
}
func WithDisks(paths ...string) MachineOption {
	return func(config *machineConfig) { config.Disks = append([]string(nil), paths...) }
}
func WithMounts(mounts ...Mount) MachineOption {
	return func(config *machineConfig) { config.Mounts = append([]Mount(nil), mounts...) }
}

// WithForwards replaces the machine-scoped forwards. Endpoints use the ADR 0016 grammar.
func WithForwards(forwards ...Forward) MachineOption {
	return func(config *machineConfig) { config.Forwards = append([]Forward(nil), forwards...) }
}

// WithVsock enables or disables the public hybrid vsock surface.
func WithVsock(enabled bool) MachineOption {
	return func(config *machineConfig) { config.Vsock = &enabled }
}

func WithMachineNetwork(network MachineNetwork) MachineOption {
	return func(config *machineConfig) {
		wire, err := network.wire()
		if err != nil {
			config.error = err
			return
		}
		config.Network = &wire
	}
}
