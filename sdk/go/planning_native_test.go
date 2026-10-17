package silo

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/vandycknick/silo/sdk/go/internal/ffi"
)

func TestPlanningNative(t *testing.T) {
	if os.Getenv("SILO_GO_FFI_PATH") == "" && os.Getenv("SILO_TEST_EMBEDDED_FFI") != "1" {
		t.Skip("actual native bridge required")
	}
	root := t.TempDir()
	home := filepath.Join(root, "absent-home")
	t.Setenv("SILO_HOME", home)
	t.Setenv("HOME", home)
	t.Setenv("SILO_RUNTIME_ROOT", filepath.Join(root, "absent-runtime"))
	for _, vector := range []struct {
		input string
		bytes uint64
	}{
		{"8gb", 8 << 30}, {"8GB", 8 << 30}, {"8g", 8 << 30}, {"8GiB", 8 << 30},
		{" \t8 \n gIb \t", 8 << 30}, {"512mb", 512 << 20}, {"512M", 512 << 20},
		{"512MiB", 512 << 20}, {"4294967295m", (1<<32 - 1) << 20},
		{"4194303g", 4194303 << 30},
	} {
		for _, parse := range []func(string) (ByteSize, error){ParseMachineMemory, ParseRootDiskSize} {
			got, err := parse(vector.input)
			if err != nil || got.Bytes() != vector.bytes {
				t.Fatalf("parse(%q) = %v, %v; want %d", vector.input, got, err, vector.bytes)
			}
		}
	}
	for _, input := range []string{"", "0g", "0mb", "1.5gb", "-8gb", "+8gb", "8", "8tb", "8 g b", "18446744073709551616m", "18446744073709551615g", "secret-value\n"} {
		for _, parse := range []func(string) (ByteSize, error){ParseMachineMemory, ParseRootDiskSize} {
			_, err := parse(input)
			if !IsErrorKind(err, ErrorInvalidArgument) || strings.Contains(err.Error(), "secret-value") {
				t.Fatalf("invalid input error = %v", err)
			}
		}
	}
	for _, input := range []string{"4294967296m", "4194304g"} {
		if _, err := ParseMachineMemory(input); !IsErrorKind(err, ErrorInvalidArgument) || !strings.Contains(err.Error(), "too large") {
			t.Fatalf("memory overflow: %v", err)
		}
	}
	for _, vector := range []struct {
		input string
		bytes uint64
	}{
		{"17592186044415m", ^uint64(0) & ^uint64(1<<20-1)},
		{"17179869183g", 17179869183 << 30},
	} {
		got, err := ParseRootDiskSize(vector.input)
		if err != nil || got.Bytes() != vector.bytes {
			t.Fatalf("disk maximum = %v, %v", got, err)
		}
	}
	for _, input := range []string{"17592186044416m", "17179869184g"} {
		if _, err := ParseRootDiskSize(input); !IsErrorKind(err, ErrorInvalidArgument) {
			t.Fatalf("disk overflow: %v", err)
		}
	}
	pattern := regexp.MustCompile(`^[a-z]+-[a-z]+-[0-9a-f]{4}$`)
	names := make(map[string]bool)
	for i := 0; i < 128; i++ {
		name, err := ProposeMachineName()
		if err != nil || !pattern.MatchString(name) {
			t.Fatalf("proposal = %q, %v", name, err)
		}
		names[name] = true
	}
	if len(names) < 120 {
		t.Fatalf("insufficient proposal entropy: %d", len(names))
	}
	for _, request := range []string{`null`, `[]`, `{}`, `{"operation":"name","input":"secret-value"}`, `{"operation":"secret-value"}`, `{"operation":"memory"}`, `{"operation":"disk","input":8}`, `{"operation":"memory","input":"8gb","extra":true}`} {
		_, err := ffi.PlanningQuery([]byte(request))
		if err == nil || strings.Contains(err.Error(), "secret-value") {
			t.Fatalf("strict query error: %v", err)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("planning created state: %v, %v", entries, err)
	}
	if Gigabytes(8).Bytes() != 8_000_000_000 || Megabytes(512).Bytes() != 512_000_000 {
		t.Fatal("decimal constructors changed")
	}
}
