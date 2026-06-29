// Package native wraps the Rust bento-policy C ABI.
//
// Go never reads Rust policy structs directly. The Rust side returns opaque
// handles for long-lived policy state and short-lived HTTP condition contexts.
// Complex load-time data crosses the boundary as JSON: Go copies the
// Rust-owned buffer, frees it with bento_policy_buffer_free, unmarshals into Go
// DTOs, and then builds its own runtime evaluator indexes. Compiled CEL stays
// in Rust and is referenced by condition id.
package native

/*
#include "bento_policy.h"
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"runtime"
	"unsafe"
)

type Status int

const (
	StatusOK              Status = C.BENTO_POLICY_OK
	StatusLoadError       Status = C.BENTO_POLICY_LOAD_ERROR
	StatusInvalidArgument Status = C.BENTO_POLICY_INVALID_ARGUMENT
	StatusEvalError       Status = C.BENTO_POLICY_EVAL_ERROR
	StatusPanic           Status = C.BENTO_POLICY_PANIC
)

type Policy struct {
	ptr *C.bento_policy_t
}

type HTTPContext struct {
	ptr *C.bento_policy_http_context_t
}

type HTTPConditionContextInput struct {
	Method  string              `json:"method"`
	Host    string              `json:"host"`
	Path    string              `json:"path"`
	Query   map[string][]string `json:"query"`
	Headers map[string][]string `json:"headers"`
}

func ParseSource(filename string, source []byte) (*Policy, Status, []byte, error) {
	filenameBytes := []byte(filename)
	var rawPolicy *C.bento_policy_t
	var rawError C.bento_policy_buffer_t
	status := Status(C.bento_policy_parse_source(bytesView(filenameBytes), bytesView(source), &rawPolicy, &rawError))
	runtime.KeepAlive(filenameBytes)
	runtime.KeepAlive(source)
	return finishParse(status, rawPolicy, rawError)
}

func finishParse(status Status, rawPolicy *C.bento_policy_t, rawError C.bento_policy_buffer_t) (*Policy, Status, []byte, error) {
	errorJSON := copyBuffer(rawError)
	if status != StatusOK {
		return nil, status, errorJSON, nil
	}
	if rawPolicy == nil {
		return nil, status, nil, fmt.Errorf("bento policy parser returned nil policy")
	}
	policy := &Policy{ptr: rawPolicy}
	runtime.SetFinalizer(policy, (*Policy).Close)
	return policy, status, nil, nil
}

func (p *Policy) SnapshotJSON() ([]byte, error) {
	if p == nil || p.ptr == nil {
		return nil, fmt.Errorf("policy is closed")
	}
	var rawJSON C.bento_policy_buffer_t
	status := Status(C.bento_policy_snapshot_json(p.ptr, &rawJSON))
	payload := copyBuffer(rawJSON)
	runtime.KeepAlive(p)
	if status != StatusOK {
		return nil, nativeError(status, payload)
	}
	// The returned buffer belonged to Rust until copyBuffer copied and freed it.
	// Callers can safely unmarshal this byte slice without holding Rust memory.
	return payload, nil
}

func (p *Policy) EvaluateHTTPCondition(conditionID uint32, context *HTTPContext) (bool, error) {
	if conditionID == 0 {
		return true, nil
	}
	if p == nil || p.ptr == nil {
		return false, fmt.Errorf("policy is closed")
	}
	if context == nil || context.ptr == nil {
		return false, fmt.Errorf("HTTP condition context is closed")
	}
	var matches C.bool
	var rawError C.bento_policy_buffer_t
	status := Status(C.bento_policy_http_condition_evaluate(p.ptr, C.uint32_t(conditionID), context.ptr, &matches, &rawError))
	errorJSON := copyBuffer(rawError)
	runtime.KeepAlive(p)
	runtime.KeepAlive(context)
	if status != StatusOK {
		return false, nativeError(status, errorJSON)
	}
	return bool(matches), nil
}

func (p *Policy) Close() {
	if p == nil || p.ptr == nil {
		return
	}
	C.bento_policy_free(p.ptr)
	p.ptr = nil
	runtime.SetFinalizer(p, nil)
}

func NewHTTPContext(input HTTPConditionContextInput) (*HTTPContext, error) {
	// This JSON handoff is request-scoped and intentionally narrow: Go has
	// already normalized method, host, query, and headers for the policy engine;
	// Rust only receives enough data to evaluate compiled HTTP CEL conditions.
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("encode HTTP condition context: %w", err)
	}
	var rawContext *C.bento_policy_http_context_t
	var rawError C.bento_policy_buffer_t
	status := Status(C.bento_policy_http_context_from_json(bytesView(payload), &rawContext, &rawError))
	runtime.KeepAlive(payload)
	errorJSON := copyBuffer(rawError)
	if status != StatusOK {
		return nil, nativeError(status, errorJSON)
	}
	if rawContext == nil {
		return nil, fmt.Errorf("bento policy returned nil HTTP condition context")
	}
	context := &HTTPContext{ptr: rawContext}
	runtime.SetFinalizer(context, (*HTTPContext).Close)
	return context, nil
}

func (c *HTTPContext) Close() {
	if c == nil || c.ptr == nil {
		return
	}
	C.bento_policy_http_context_free(c.ptr)
	c.ptr = nil
	runtime.SetFinalizer(c, nil)
}

func bytesView(value []byte) C.bento_policy_bytes_t {
	if len(value) == 0 {
		return C.bento_policy_bytes_t{}
	}
	return C.bento_policy_bytes_t{
		ptr: (*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(value))),
		len: C.size_t(len(value)),
	}
}

func copyBuffer(buffer C.bento_policy_buffer_t) []byte {
	if buffer.ptr == nil || buffer.len == 0 {
		return nil
	}
	// C.GoBytes copies the Rust-owned allocation into Go memory. After this point
	// the Rust allocation must be returned through the matching free function.
	bytes := C.GoBytes(unsafe.Pointer(buffer.ptr), C.int(buffer.len))
	C.bento_policy_buffer_free(buffer)
	return bytes
}

type errorMessage struct {
	Message string `json:"message"`
}

func nativeError(status Status, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("bento policy native call failed with status %d", status)
	}
	var decoded errorMessage
	if err := json.Unmarshal(payload, &decoded); err == nil && decoded.Message != "" {
		return fmt.Errorf("bento policy native call failed with status %d: %s", status, decoded.Message)
	}
	return fmt.Errorf("bento policy native call failed with status %d: %s", status, string(payload))
}
