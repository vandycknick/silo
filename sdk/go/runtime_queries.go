package silo

import (
	"context"
	"encoding/json"
)

type MachineIssue struct {
	Component string `json:"component"`
	Message   string `json:"message"`
}
type MachineInventoryEntry struct {
	ID     string
	Name   string
	Data   *MachineData
	Issues []MachineIssue
}

// Inventory keeps indexed identity and per-record issues even when a machine is unreadable.
func (runtime *Runtime) Inventory(ctx context.Context) ([]MachineInventoryEntry, error) {
	data, err := runtime.query(ctx, []byte(`{"operation":"inventory"}`))
	if err != nil {
		return nil, err
	}
	var wires []struct {
		ID     string          `json:"id"`
		Name   string          `json:"name"`
		Data   json.RawMessage `json:"data"`
		Issues []MachineIssue  `json:"issues"`
	}
	if err := json.Unmarshal(data, &wires); err != nil {
		return nil, err
	}
	entries := make([]MachineInventoryEntry, 0, len(wires))
	for _, wire := range wires {
		entry := MachineInventoryEntry{ID: wire.ID, Name: wire.Name, Issues: wire.Issues}
		if string(wire.Data) != "null" {
			entry.Data, err = decodeMachineData(wire.Data)
			if err != nil {
				return nil, err
			}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// PolicySecretsReady checks actual start-time resolution without exposing values or mutating stores.
// An empty machine reference checks prospective creation against Home secrets only.
func (runtime *Runtime) PolicySecretsReady(ctx context.Context, policy *NetworkPolicy, machine string) (bool, error) {
	if policy == nil {
		return false, newError(ErrorInvalidArgument, "", "policy is required")
	}
	request := struct {
		Operation  string  `json:"operation"`
		PolicyJSON string  `json:"policy_json"`
		Machine    *string `json:"machine,omitempty"`
	}{Operation: "secret_readiness", PolicyJSON: policy.JSON()}
	if machine != "" {
		request.Machine = &machine
	}
	data, err := json.Marshal(request)
	if err != nil {
		return false, err
	}
	data, err = runtime.query(ctx, data)
	if err != nil {
		return false, err
	}
	var result struct {
		Ready bool `json:"ready"`
	}
	err = json.Unmarshal(data, &result)
	return result.Ready, err
}

func (runtime *Runtime) query(ctx context.Context, request []byte) ([]byte, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	runtime.mutex.RLock()
	defer runtime.mutex.RUnlock()
	if runtime.closed {
		return nil, newError(ErrorClosed, "", "runtime is closed")
	}
	data, err := runtime.native.Query(request)
	if err != nil {
		return nil, fromNativeError(err)
	}
	return data, nil
}
