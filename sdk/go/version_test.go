package silo

import (
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

func TestABI3RejectsActualABI2Bridge(t *testing.T) {
	if os.Getenv("SILO_ABI2_CHILD") == "1" {
		_, err := VerifiedNativeABIVersion()
		if !IsErrorKind(err, ErrorABIMismatch) || !strings.Contains(err.Error(), "bridge ABI 2, SDK requires ABI 3") {
			t.Fatalf("old ABI error = %v", err)
		}
		return
	}
	old := os.Getenv("SILO_TEST_OLD_FFI_PATH")
	if old == "" {
		t.Skip("SILO_TEST_OLD_FFI_PATH must name an actual older bridge")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestABI3RejectsActualABI2Bridge$")
	command.Env = append(os.Environ(), "SILO_ABI2_CHILD=1", "SILO_GO_FFI_PATH="+old)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, output)
	}
}
