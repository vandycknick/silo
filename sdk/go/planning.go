package silo

import (
	"encoding/json"

	"github.com/vandycknick/silo/sdk/go/internal/ffi"
)

// ParseMachineMemory parses CLI integer memory units (m/mb/mib/g/gb/gib).
// All units are binary, so 8gb is 8 GiB. Zero and values above u32 MiB fail.
// Parsing opens no runtime, home directory, database, or network connection.
func ParseMachineMemory(input string) (ByteSize, error) {
	return parsePlanningSize("memory", input)
}

// ParseRootDiskSize parses CLI binary storage units into nonzero bytes.
// Units are case-insensitive; surrounding and number/unit whitespace is accepted.
func ParseRootDiskSize(input string) (ByteSize, error) {
	return parsePlanningSize("disk", input)
}

func parsePlanningSize(operation, input string) (ByteSize, error) {
	request := struct {
		Operation string `json:"operation"`
		Input     string `json:"input"`
	}{operation, input}
	var response struct {
		Bytes uint64 `json:"bytes"`
	}
	if err := planningQuery(request, &response); err != nil {
		return ByteSize{}, err
	}
	return Bytes(response.Bytes), nil
}

// ProposeMachineName uses Silo's adjective-noun-fourhex generator.
// The proposal is neither checked for availability nor reserved. No runtime is opened.
func ProposeMachineName() (string, error) {
	request := struct {
		Operation string `json:"operation"`
	}{"name"}
	var response struct {
		Name string `json:"name"`
	}
	if err := planningQuery(request, &response); err != nil {
		return "", err
	}
	return response.Name, nil
}

func planningQuery(request interface{}, response interface{}) error {
	if err := ffi.Load(Version, NativeABIVersion); err != nil {
		return fromNativeError(err)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return newError(ErrorInvalidArgument, "", "encode planning query failed")
	}
	data, err := ffi.PlanningQuery(encoded)
	if err != nil {
		return fromNativeError(err)
	}
	if err := json.Unmarshal(data, response); err != nil {
		return newError(ErrorInvalidArgument, "", "decode planning response failed")
	}
	return nil
}
