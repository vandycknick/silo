package silo

import (
	"context"
	"testing"
)

func testRuntimeComponents() RuntimeComponents {
	return RuntimeComponents{
		SupervisorPath: "/runtime/vmm", NetdPath: "/runtime/netd",
		KernelPath: "/runtime/kernel", InitramfsPath: "/runtime/initramfs",
		AgentPath: "/runtime/agent", AssetDir: "/runtime/assets",
	}
}

func TestRuntimeComponentsRejectMixedOptionsBeforeLoadingBridge(t *testing.T) {
	exact := WithRuntimeComponents(testRuntimeComponents())
	for _, other := range []RuntimeOption{
		WithRuntimeRoot("/runtime"), WithSupervisorPath("/runtime/vmm"),
		WithRuntimeRoot(""), WithSupervisorPath(""),
	} {
		for _, options := range [][]RuntimeOption{{exact, other}, {other, exact}} {
			_, err := Open(context.Background(), options...)
			if !IsErrorKind(err, ErrorInvalidArgument) {
				t.Fatalf("mixed Open error = %v, want ErrorInvalidArgument", err)
			}
		}
	}
}

func TestRuntimeComponentsRejectIncompleteAndRelativePathsBeforeLoadingBridge(t *testing.T) {
	for field := range 6 {
		for _, invalid := range []string{"", "   ", "relative/component"} {
			value := testRuntimeComponents()
			fields := []*string{&value.SupervisorPath, &value.NetdPath, &value.KernelPath, &value.InitramfsPath, &value.AgentPath, &value.AssetDir}
			*fields[field] = invalid
			_, err := Open(context.Background(), WithRuntimeComponents(value))
			if !IsErrorKind(err, ErrorInvalidArgument) {
				t.Fatalf("field %d value %q: error = %v, want ErrorInvalidArgument", field, invalid, err)
			}
		}
	}
}
