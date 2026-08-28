package silo

import (
	"testing"
	"time"

	"github.com/vandycknick/silo/sdk/go/internal/ffi"
)

func TestExecutionOptionsCopyInputs(t *testing.T) {
	args := []string{"one"}
	env := map[string]string{"A": "B"}
	data := []byte{1, 2}
	request, err := executionRequest("echo", nil, []ExecOption{WithExecAdditionalArgs(args...), WithExecEnv(env), WithExecStdin(data), WithExecTimeout(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	args[0] = "changed"
	env["A"] = "changed"
	data[0] = 9
	if string(request) == "" {
		t.Fatal("empty request")
	}
}
func TestExecutionStdinModesAreExclusive(t *testing.T) {
	_, err := executionRequest("echo", nil, []ExecOption{WithExecStdinPipe(), WithExecStdin([]byte("x"))})
	if !IsErrorKind(err, ErrorInvalidArgument) {
		t.Fatalf("error = %v", err)
	}
}
func TestDecodeExecutionOutputPreservesBinaryBytes(t *testing.T) {
	output, err := decodeOutput(&ffi.ExecutionOutput{
		Result: []byte(`{"kind":"exited","code":7}`),
		Stdout: []byte{0, 255, 128},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := output.StdoutBytes(); len(got) != 3 || got[1] != 255 {
		t.Fatalf("stdout = %v", got)
	}
	if output.Result().Code == nil || *output.Result().Code != 7 {
		t.Fatalf("result = %#v", output.Result())
	}
}
