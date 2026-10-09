package silo

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestVerifiedNativeABIVersion(t *testing.T) {
	if os.Getenv("SILO_GO_FFI_PATH") == "" && os.Getenv("SILO_TEST_EMBEDDED_FFI") != "1" {
		t.Skip("actual native bridge or qualified embedded bridge required")
	}
	actual, err := VerifiedNativeABIVersion()
	if err != nil || actual != NativeABIVersion {
		t.Fatalf("verified ABI = %d, %v; required %d", actual, err, NativeABIVersion)
	}
}

func TestRejectsIncompatibleNativeBridge(t *testing.T) {
	if os.Getenv("SILO_ABI_MISMATCH_CHILD") == "1" {
		_, err := VerifiedNativeABIVersion()
		if !IsErrorKind(err, ErrorABIMismatch) || !strings.Contains(err.Error(), fmt.Sprintf("SDK requires ABI %d", NativeABIVersion)) {
			t.Fatalf("incompatible ABI error = %v", err)
		}
		return
	}
	incompatible := os.Getenv("SILO_TEST_INCOMPATIBLE_FFI_PATH")
	if incompatible == "" {
		t.Skip("SILO_TEST_INCOMPATIBLE_FFI_PATH must name an actual incompatible bridge")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestRejectsIncompatibleNativeBridge$")
	command.Env = append(os.Environ(), "SILO_ABI_MISMATCH_CHILD=1", "SILO_GO_FFI_PATH="+incompatible)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, output)
	}
}

func TestNativeABIVersionConstant(t *testing.T) {
	const got uint32 = NativeABIVersion
	if got != 1 {
		t.Fatalf("required ABI = %d", got)
	}
}
