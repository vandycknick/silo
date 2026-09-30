package silo

import (
	"context"
	"encoding/json"
	"maps"
	"time"
)

// MachineUpdate changes durable settings of a stopped machine. Nil means unchanged.
// Labels and Forwards replace the complete collection, including an explicitly empty collection.
type MachineUpdate struct {
	Name                 *string
	Labels               *map[string]string
	CPUs                 *uint8
	Memory               *ByteSize
	RootDiskSize         *ByteSize
	NestedVirtualization *bool
	Rosetta              *bool
	Forwards             *[]Forward
	Vsock                *bool
	Network              *MachineNetwork
	Policy               *NetworkPolicy
	ClearPolicy          bool
	GuestUser            *GuestUser
	ClearGuestUser       bool
	GuestAgent           *MachineAgent
	Publish              *GuestPublish
	ClearPublish         bool
}

func (machine *Machine) Update(ctx context.Context, update MachineUpdate) (*MachineData, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	request := struct {
		Name                 *string             `json:"name,omitempty"`
		Labels               *map[string]string  `json:"labels,omitempty"`
		CPUs                 *uint8              `json:"cpus,omitempty"`
		Memory               *uint64             `json:"memory_bytes,omitempty"`
		RootDiskSize         *uint64             `json:"root_disk_size_bytes,omitempty"`
		NestedVirtualization *bool               `json:"nested_virtualization,omitempty"`
		Rosetta              *bool               `json:"rosetta,omitempty"`
		Forwards             *[]Forward          `json:"forwards,omitempty"`
		Vsock                *bool               `json:"vsock,omitempty"`
		Network              *machineNetworkWire `json:"network,omitempty"`
		PolicyJSON           *string             `json:"policy_json,omitempty"`
		ClearPolicy          bool                `json:"clear_policy"`
		GuestUser            *GuestUser          `json:"guest_user,omitempty"`
		ClearGuestUser       bool                `json:"clear_guest_user"`
		GuestAgent           *MachineAgent       `json:"guest_agent,omitempty"`
		Publish              *GuestPublish       `json:"publish,omitempty"`
		ClearPublish         bool                `json:"clear_publish"`
	}{Name: update.Name, CPUs: update.CPUs, NestedVirtualization: update.NestedVirtualization, Rosetta: update.Rosetta, Vsock: update.Vsock, ClearPolicy: update.ClearPolicy, GuestUser: update.GuestUser, ClearGuestUser: update.ClearGuestUser}
	if update.Labels != nil {
		labels := maps.Clone(*update.Labels)
		if labels == nil {
			labels = map[string]string{}
		}
		request.Labels = &labels
	}
	if update.Forwards != nil {
		forwards := append([]Forward{}, (*update.Forwards)...)
		request.Forwards = &forwards
	}
	if update.Memory != nil {
		value := update.Memory.Bytes()
		request.Memory = &value
	}
	if update.RootDiskSize != nil {
		value := update.RootDiskSize.Bytes()
		request.RootDiskSize = &value
	}
	if update.Network != nil {
		wire, err := update.Network.wire()
		if err != nil {
			return nil, err
		}
		request.Network = &wire
	}
	if update.Policy != nil {
		value := update.Policy.JSON()
		request.PolicyJSON = &value
	}
	request.GuestAgent = update.GuestAgent
	request.Publish = update.Publish
	request.ClearPublish = update.ClearPublish
	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	machine.mutex.RLock()
	defer machine.mutex.RUnlock()
	if machine.closed {
		return nil, newError(ErrorClosed, "", "machine is closed")
	}
	result, err := machine.native.Update(data)
	if err != nil {
		return nil, fromNativeError(err)
	}
	return decodeMachineData(result)
}

// StopOptions bounds graceful shutdown. Force escalates against the same run after timeout,
// with an additional ten-second bounded kill wait. Zero Timeout uses Rust's default.
type StopOptions struct {
	Timeout time.Duration
	Force   bool
}

func (machine *Machine) StopWith(ctx context.Context, options StopOptions) (*MachineData, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if options.Timeout < 0 {
		return nil, newError(ErrorInvalidArgument, "", "stop timeout must not be negative")
	}
	request := struct {
		Timeout *uint64 `json:"timeout_ms,omitempty"`
		Force   bool    `json:"force"`
	}{Force: options.Force}
	if options.Timeout > 0 {
		value := uint64((options.Timeout-1)/time.Millisecond) + 1
		request.Timeout = &value
	}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	machine.mutex.RLock()
	defer machine.mutex.RUnlock()
	if machine.closed {
		return nil, newError(ErrorClosed, "", "machine is closed")
	}
	result, err := machine.native.StopWith(data)
	if err != nil {
		return nil, fromNativeError(err)
	}
	return decodeMachineData(result)
}

// WaitReady waits for actual guest provisioning readiness, not monitor/socket readiness.
func (machine *Machine) WaitReady(ctx context.Context, timeout time.Duration) (*MachineData, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		return nil, newError(ErrorInvalidArgument, "", "readiness timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, err := machine.Inspect(ctx)
		if err != nil {
			return nil, err
		}
		if err := validateContext(ctx); err != nil {
			return nil, err
		}
		if data.Observation == "observed" && data.Status.Kind == MachineStatusRunning && data.Status.Ready != nil && *data.Status.Ready && data.Status.GuestReady != nil && *data.Status.GuestReady {
			return data, nil
		}
		if data.Status.Kind == MachineStatusStopped || data.Status.Kind == MachineStatusError || data.Status.Kind == MachineStatusStopping {
			message := "machine cannot become guest ready: " + string(data.Status.Kind)
			if data.LastError != nil {
				message += ": " + *data.LastError
			}
			if data.Status.Message != nil {
				message += ": " + *data.Status.Message
			}
			return nil, newError(ErrorInvalidArgument, machine.ID(), message)
		}
		select {
		case <-ctx.Done():
			return nil, contextError(ctx.Err())
		case <-ticker.C:
		}
	}
}
