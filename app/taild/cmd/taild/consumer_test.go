package main

import (
	"context"
	"fmt"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCleanPublicConsumerAndActualCheckBinary(t *testing.T) {
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
func main(){_,e:=silo.Open(context.Background(),silo.WithHome(os.Args[1]),silo.WithRuntimeRoot(os.Args[1]));if !silo.IsErrorKind(e,silo.ErrorRuntimeComponentInvalid){fmt.Fprintln(os.Stderr,e);os.Exit(1)}}
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
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	writeConfig := func(home, root string) {
		t.Helper()
		body := fmt.Sprintf("home: %q\nsecrets_dir: %q\n", home, t.TempDir())
		if root != "" {
			body += fmt.Sprintf("runtime_root: %q\n", root)
		}
		if e := os.WriteFile(configPath, []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
	}
	writeConfig(home, "")
	output, e := run(module, binary, "--check", "--config", configPath)
	if os.Geteuid() == 0 {
		if e == nil || !strings.Contains(output, "refuses to run as root") {
			t.Fatalf("root check: %v %s", e, output)
		}
		testfixture.Unavailable(t, "nonroot prepared-home binary check requires a nonroot uid")
	}
	if e == nil || !strings.Contains(output, "runtime is missing") {
		t.Fatalf("missing-runtime check: %v %s", e, output)
	}
	writeConfig("/", "")
	output, e = run(module, binary, "--check", "--config", configPath)
	if e == nil || !strings.Contains(output, "not owned") {
		t.Fatalf("foreign-home check: %v %s", e, output)
	}
	root := testfixture.Path(t, "SILO_TEST_RUNTIME_ROOT", true)
	writeConfig(home, root)
	output, e = run(module, binary, "--check", "--config", configPath)
	if e != nil || !strings.Contains(output, "configuration and runtime ready") {
		t.Fatalf("prepared-home check: %v %s", e, output)
	}
	if _, e = os.Stat(filepath.Join(home, "taild", "tsnet")); !os.IsNotExist(e) {
		t.Fatal("--check initialized a tailnet node")
	}
}
