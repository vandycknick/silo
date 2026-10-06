package main

import (
	"context"
	"fmt"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	silo "github.com/vandycknick/silo/sdk/go"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCleanPublicConsumerAndManagedHelperBinary(t *testing.T) {
	testfixture.Path(t, "SILO_GO_FFI_PATH", false)
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate module")
	}
	module := filepath.Clean(filepath.Join(filepath.Dir(source), "../.."))
	sdk := filepath.Clean(filepath.Join(module, "../../sdk/go"))
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	run := func(dir string, args ...string) (string, error) {
		t.Helper()
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "CGO_ENABLED=1", "GOFLAGS=-mod=mod")
		b, e := cmd.CombinedOutput()
		return string(b), e
	}
	consumer := t.TempDir()
	gomod := fmt.Sprintf("module example.com/clean-taild-consumer\n\ngo 1.26.6\n\ntoolchain go1.26.8\n\nrequire github.com/vandycknick/silo/sdk/go v0.0.0\nreplace github.com/vandycknick/silo/sdk/go => %s\n", sdk)
	if e := os.WriteFile(filepath.Join(consumer, "go.mod"), []byte(gomod), 0600); e != nil {
		t.Fatal(e)
	}
	code := `package main
import("context"; "fmt"; "os"; silo "github.com/vandycknick/silo/sdk/go")
func main(){ctx:=context.Background();_,e:=silo.Open(ctx,silo.WithHome(os.Args[1]),silo.WithRuntimeRoot(os.Args[1]));if !silo.IsErrorKind(e,silo.ErrorRuntimeComponentInvalid){fmt.Fprintln(os.Stderr,e);os.Exit(1)};r,e:=silo.Open(ctx,silo.WithHome(os.Args[1]),silo.WithRuntimeRoot(os.Getenv("SILO_TEST_RUNTIME_ROOT")));if e!=nil{panic(e)};defer r.Close();p,e:=silo.ParseNetworkPolicyHCL("tailscale \"vm\" {}");if e!=nil{panic(e)};check,e:=r.CheckPolicySecrets(ctx,p,"",nil);if e!=nil||check.Status!=silo.PolicySecretsReady{panic(fmt.Sprintf("%+v %v",check,e))}}
`
	if e := os.WriteFile(filepath.Join(consumer, "main.go"), []byte(code), 0600); e != nil {
		t.Fatal(e)
	}
	if output, e := run(consumer, "go", "mod", "tidy"); e != nil {
		t.Fatalf("clean consumer tidy: %v\n%s", e, output)
	}
	if output, e := run(consumer, "go", "run", ".", t.TempDir()); e != nil {
		t.Fatalf("clean public SDK runtime validation: %v\n%s", e, output)
	}
	binary := filepath.Join(t.TempDir(), "taild")
	if output, e := run(module, "go", "build", "-o", binary, "./cmd/taild"); e != nil {
		t.Fatalf("taild build: %v\n%s", e, output)
	}
	home := t.TempDir()
	for _, command := range []string{"version", "--version", "--help"} {
		cmd := exec.CommandContext(ctx, binary, command)
		cmd.Env = []string{"HOME=" + home, "SILO_HOME=" + home, "SILO_GO_FFI_PATH=" + filepath.Join(home, "missing-bridge")}
		bytes, e := cmd.CombinedOutput()
		output := string(bytes)
		if e != nil {
			t.Fatalf("isolated helper command: %v %s", e, output)
		}
		if strings.Contains(command, "version") && (!strings.Contains(output, "SDK "+silo.Version+" runtime unavailable") || !strings.Contains(output, "verified unavailable")) {
			t.Fatal("version claimed unverified runtime or ABI", output)
		}
	}
	for _, args := range [][]string{nil, {"--check"}, {"--config", filepath.Join(home, "missing-config")}, {"stop-vms"}, {"install-runtime"}} {
		output, e := run(module, append([]string{binary}, args...)...)
		if e == nil {
			t.Fatal("standalone helper invocation accepted", args)
		}
		exit, ok := e.(*exec.ExitError)
		if !ok || exit.ExitCode() != 2 {
			t.Fatalf("configuration error must exit 2: %v %s", e, output)
		}
	}
	if entries, e := os.ReadDir(home); e != nil || len(entries) != 0 {
		t.Fatal("offline helper command wrote Home", entries, e)
	}
}
