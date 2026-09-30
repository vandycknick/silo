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

type PolicySecretsStatus string

const (
	PolicySecretsReady       PolicySecretsStatus = "ready"
	PolicySecretsMissing     PolicySecretsStatus = "missing"
	PolicySecretsUnavailable PolicySecretsStatus = "unavailable"
)

// PolicySecretsCheck contains names and error categories only, never secret values or paths.
type PolicySecretsCheck struct {
	Status       PolicySecretsStatus        `json:"status"`
	Slots        []NetworkSecretSlot        `json:"slots,omitempty"`
	Requirements []NetworkSecretRequirement `json:"requirements,omitempty"`
	Slot         string                     `json:"slot,omitempty"`
	Key          string                     `json:"key,omitempty"`
	Code         string                     `json:"code,omitempty"`
}

// CheckPolicySecrets uses the native start resolver. Empty machine checks prospective
// Home scope. Nonempty overrides replace the whole store-derived set, as at Start.
func (runtime *Runtime) CheckPolicySecrets(ctx context.Context, policy *NetworkPolicy, machine string, overrides map[string]string) (PolicySecretsCheck, error) {
	if policy == nil {
		return PolicySecretsCheck{}, newError(ErrorInvalidArgument, "", "policy is required")
	}
	request := struct {
		Operation  string            `json:"operation"`
		PolicyJSON string            `json:"policy_json"`
		Machine    string            `json:"machine,omitempty"`
		Secrets    map[string]string `json:"secrets,omitempty"`
	}{"check_policy_secrets", policy.JSON(), machine, overrides}
	data, err := json.Marshal(request)
	if err != nil {
		return PolicySecretsCheck{}, err
	}
	data, err = runtime.query(ctx, data)
	if err != nil {
		return PolicySecretsCheck{}, err
	}
	var result PolicySecretsCheck
	err = json.Unmarshal(data, &result)
	return result, err
}
