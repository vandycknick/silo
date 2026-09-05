package silo

import (
	"encoding/json"
	"time"
)

type machineDataWire struct {
	ID              string               `json:"id"`
	Name            string               `json:"name"`
	MachineDir      string               `json:"machine_dir"`
	CreatedAt       int64                `json:"created_at_unix_ms"`
	ModifiedAt      int64                `json:"modified_at_unix_ms"`
	ImageRef        string               `json:"image_ref"`
	Retention       MachineRetention     `json:"retention"`
	Process         ProcessConfig        `json:"process"`
	TemplateName    *string              `json:"template_name"`
	AgentMode       *MachineAgent        `json:"agent_mode"`
	RootFS          *machineRootFSWire   `json:"rootfs"`
	RootDiskSize    *uint64              `json:"root_disk_size_bytes"`
	Labels          map[string]string    `json:"labels"`
	Metadata        map[string]string    `json:"metadata"`
	Forwards        []Forward            `json:"forwards"`
	Vsock           *VsockConfig         `json:"vsock"`
	Network         machineNetworkWire   `json:"network"`
	Agent           MachineAgent         `json:"agent"`
	Status          MachineStatus        `json:"status"`
	BootReport      *MachineBootReport   `json:"boot_report"`
	ProvisionReport *provisionReportWire `json:"provision_report"`
	StartedAt       *int64               `json:"started_at_unix_ms"`
	LastError       *string              `json:"last_error"`
	UpdatedAt       int64                `json:"updated_at_unix_ms"`
}
type machineRootFSWire struct {
	SourceKind             string  `json:"source_kind"`
	RequestedReference     string  `json:"requested_reference"`
	SelectedReference      *string `json:"selected_reference"`
	SelectedManifestDigest *string `json:"selected_manifest_digest"`
	ConfigDigest           *string `json:"config_digest"`
	ImageID                *string `json:"image_id"`
	RootDiskPath           string  `json:"root_disk_path"`
	RootDiskSize           uint64  `json:"root_disk_size_bytes"`
	CreatedAt              int64   `json:"created_at_unix_ms"`
}
type provisionReportWire struct {
	Status     MachineProvisionStatus `json:"status"`
	StartedAt  int64                  `json:"started_at_unix_ms"`
	FinishedAt int64                  `json:"finished_at_unix_ms"`
	Duration   uint64                 `json:"duration_ms"`
	Steps      []provisionStepWire    `json:"steps"`
	Message    *string                `json:"message"`
}
type provisionStepWire struct {
	ID            string                        `json:"id"`
	Status        MachineProvisionStepStatus    `json:"status"`
	FailurePolicy MachineProvisionFailurePolicy `json:"failure_policy"`
	Changed       bool                          `json:"changed"`
	Backend       *string                       `json:"backend"`
	Duration      uint64                        `json:"duration_ms"`
	Message       *string                       `json:"message"`
	ErrorChain    *string                       `json:"error_chain"`
}

func decodeMachineData(data []byte) (*MachineData, error) {
	var wire machineDataWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, newError(ErrorUnknown, "", "decode native machine data: "+err.Error())
	}
	result := &MachineData{ID: wire.ID, Name: wire.Name, MachineDir: wire.MachineDir, CreatedAt: time.UnixMilli(wire.CreatedAt), ModifiedAt: time.UnixMilli(wire.ModifiedAt), ImageRef: wire.ImageRef, Retention: wire.Retention, Process: wire.Process, TemplateName: wire.TemplateName, AgentMode: wire.AgentMode, Labels: wire.Labels, Metadata: wire.Metadata, Network: MachineNetwork{Kind: wire.Network.Kind, Name: wire.Network.Name}, Agent: wire.Agent, Status: wire.Status, BootReport: wire.BootReport, LastError: wire.LastError, UpdatedAt: time.UnixMilli(wire.UpdatedAt)}
	result.Forwards = wire.Forwards
	result.Vsock = wire.Vsock
	result.Network.Publish = wire.Network.Publish
	if wire.Network.PolicyJSON != "" {
		result.Network.Policy = &NetworkPolicy{canonicalJSON: wire.Network.PolicyJSON}
	}
	if wire.RootDiskSize != nil {
		size := Bytes(*wire.RootDiskSize)
		result.RootDiskSize = &size
	}
	if wire.StartedAt != nil {
		value := time.UnixMilli(*wire.StartedAt)
		result.StartedAt = &value
	}
	if wire.RootFS != nil {
		result.RootFS = &MachineRootFS{SourceKind: wire.RootFS.SourceKind, RequestedReference: wire.RootFS.RequestedReference, SelectedReference: wire.RootFS.SelectedReference, SelectedManifestDigest: wire.RootFS.SelectedManifestDigest, ConfigDigest: wire.RootFS.ConfigDigest, ImageID: wire.RootFS.ImageID, RootDiskPath: wire.RootFS.RootDiskPath, RootDiskSize: Bytes(wire.RootFS.RootDiskSize), CreatedAt: time.UnixMilli(wire.RootFS.CreatedAt)}
	}
	if wire.ProvisionReport != nil {
		report := &MachineProvisionReport{Status: wire.ProvisionReport.Status, StartedAt: time.UnixMilli(wire.ProvisionReport.StartedAt), FinishedAt: time.UnixMilli(wire.ProvisionReport.FinishedAt), Duration: time.Duration(wire.ProvisionReport.Duration) * time.Millisecond, Message: wire.ProvisionReport.Message}
		report.Steps = make([]MachineProvisionStepReport, len(wire.ProvisionReport.Steps))
		for index, step := range wire.ProvisionReport.Steps {
			report.Steps[index] = MachineProvisionStepReport{ID: step.ID, Status: step.Status, FailurePolicy: step.FailurePolicy, Changed: step.Changed, Backend: step.Backend, Duration: time.Duration(step.Duration) * time.Millisecond, Message: step.Message, ErrorChain: step.ErrorChain}
		}
		result.ProvisionReport = report
	}
	return result, nil
}
