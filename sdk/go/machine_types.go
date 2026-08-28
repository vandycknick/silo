package silo

import "time"

type MachineRetention string

const (
	MachineRetentionPersistent MachineRetention = "persistent"
	MachineRetentionEphemeral  MachineRetention = "ephemeral"
	MachineRetentionUnknown    MachineRetention = "unknown"
)

type MachineAgentMode string

const (
	MachineAgentDefault  MachineAgentMode = "default"
	MachineAgentCustom   MachineAgentMode = "custom"
	MachineAgentDisabled MachineAgentMode = "disabled"
	MachineAgentUnknown  MachineAgentMode = "unknown"
)

type MachineAgent struct {
	Mode MachineAgentMode `json:"mode"`
	Path string           `json:"path,omitempty"`
}

type MachineStatusKind string

const (
	MachineStatusStopped  MachineStatusKind = "stopped"
	MachineStatusStarting MachineStatusKind = "starting"
	MachineStatusRunning  MachineStatusKind = "running"
	MachineStatusStopping MachineStatusKind = "stopping"
	MachineStatusError    MachineStatusKind = "error"
	MachineStatusUnknown  MachineStatusKind = "unknown"
)

type MachineStatus struct {
	Kind       MachineStatusKind `json:"kind"`
	Ready      *bool             `json:"ready,omitempty"`
	GuestReady *bool             `json:"guest_ready,omitempty"`
	Message    *string           `json:"message,omitempty"`
}

type MachineBootMode string

const (
	MachineBootUnspecified MachineBootMode = "unspecified"
	MachineBootStandard    MachineBootMode = "standard"
	MachineBootAgentPID1   MachineBootMode = "agent-pid1"
	MachineBootInitChild   MachineBootMode = "init-child"
	MachineBootUnknown     MachineBootMode = "unknown"
)

type MachineBootReport struct {
	Mode            MachineBootMode `json:"mode"`
	RequestedInit   *string         `json:"requested_init"`
	HandoffInitPath *string         `json:"handoff_init_path"`
	ProbedInitPaths []string        `json:"probed_init_paths"`
	AgentPath       *string         `json:"agent_path"`
	AgentPID        uint32          `json:"agent_pid"`
	AgentIsPID1     bool            `json:"agent_is_pid1"`
	Message         *string         `json:"message"`
}

type MachineProvisionStatus string
type MachineProvisionStepStatus string
type MachineProvisionFailurePolicy string

const (
	MachineProvisionUnspecified        MachineProvisionStatus        = "unspecified"
	MachineProvisionSucceeded          MachineProvisionStatus        = "succeeded"
	MachineProvisionDegraded           MachineProvisionStatus        = "degraded"
	MachineProvisionSkipped            MachineProvisionStatus        = "skipped"
	MachineProvisionFailedBoot         MachineProvisionStatus        = "failed-boot"
	MachineProvisionUnknown            MachineProvisionStatus        = "unknown"
	MachineProvisionStepUnspecified    MachineProvisionStepStatus    = "unspecified"
	MachineProvisionStepSucceeded      MachineProvisionStepStatus    = "succeeded"
	MachineProvisionStepFailed         MachineProvisionStepStatus    = "failed"
	MachineProvisionStepSkipped        MachineProvisionStepStatus    = "skipped"
	MachineProvisionStepUnsupported    MachineProvisionStepStatus    = "unsupported"
	MachineProvisionStepUnknown        MachineProvisionStepStatus    = "unknown"
	MachineProvisionFailureUnspecified MachineProvisionFailurePolicy = "unspecified"
	MachineProvisionFailureBestEffort  MachineProvisionFailurePolicy = "best-effort"
	MachineProvisionFailureFailBoot    MachineProvisionFailurePolicy = "fail-boot"
	MachineProvisionFailureUnknown     MachineProvisionFailurePolicy = "unknown"
)

type MachineProvisionStepReport struct {
	ID            string                        `json:"id"`
	Status        MachineProvisionStepStatus    `json:"status"`
	FailurePolicy MachineProvisionFailurePolicy `json:"failure_policy"`
	Changed       bool                          `json:"changed"`
	Backend       *string                       `json:"backend"`
	Duration      time.Duration
	Message       *string `json:"message"`
	ErrorChain    *string `json:"error_chain"`
}
type MachineProvisionReport struct {
	Status     MachineProvisionStatus `json:"status"`
	StartedAt  time.Time
	FinishedAt time.Time
	Duration   time.Duration
	Steps      []MachineProvisionStepReport `json:"steps"`
	Message    *string                      `json:"message"`
}

type ProcessConfig struct {
	Entrypoint       *[]string         `json:"entrypoint"`
	Command          *[]string         `json:"command"`
	Environment      map[string]string `json:"environment"`
	WorkingDirectory string            `json:"working_directory"`
	User             *string           `json:"user"`
}
type MachineRootFS struct {
	SourceKind             string  `json:"source_kind"`
	RequestedReference     string  `json:"requested_reference"`
	SelectedReference      *string `json:"selected_reference"`
	SelectedManifestDigest *string `json:"selected_manifest_digest"`
	ConfigDigest           *string `json:"config_digest"`
	ImageID                *string `json:"image_id"`
	RootDiskPath           string  `json:"root_disk_path"`
	RootDiskSize           ByteSize
	CreatedAt              time.Time
}

type MachineData struct {
	ID              string
	Name            string
	MachineDir      string
	CreatedAt       time.Time
	ModifiedAt      time.Time
	ImageRef        string
	Retention       MachineRetention
	Process         ProcessConfig
	TemplateName    *string
	AgentMode       *MachineAgent
	RootFS          *MachineRootFS
	RootDiskSize    *ByteSize
	Labels          map[string]string
	Metadata        map[string]string
	Network         MachineNetwork
	Agent           MachineAgent
	Status          MachineStatus
	BootReport      *MachineBootReport
	ProvisionReport *MachineProvisionReport
	StartedAt       *time.Time
	LastError       *string
	UpdatedAt       time.Time
}
