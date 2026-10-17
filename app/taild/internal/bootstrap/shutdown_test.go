package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	silo "github.com/vandycknick/silo/sdk/go"
	daemonv1 "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestShutdownBootstrapIsExplicitAndNativeFree(t *testing.T) {
	t.Setenv("SILO_GO_FFI_PATH", "/unavailable/native/bridge")
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	wire := &daemonv1.HelperBootstrap{
		ProtocolMajor: 1, ProductVersion: silo.Version,
		DaemonGeneration: uuid.NewString(), HelperGeneration: uuid.NewString(),
		Home: []byte(root), ConfigDir: []byte(root), ControlEndpoint: []byte(filepath.Join(root, "control.sock")),
		Settings: &daemonv1.TailscaleSettings{StopBudget: durationpb.New(3 * time.Second), ShutdownMargin: durationpb.New(100 * time.Millisecond)},
	}
	input, err := Validate(wire, ShutdownOnly)
	if err != nil {
		t.Fatal(err)
	}
	if input.Config.BridgePath != "" || input.Secrets.ClientSecret != "" || os.Getenv("SILO_GO_FFI_PATH") != "/unavailable/native/bridge" {
		t.Fatal("shutdown validation touched native inputs")
	}
	if _, err := Validate(wire, Normal); err == nil {
		t.Fatal("missing native fields implicitly selected shutdown")
	}
	if _, err := Validate(wire, Mode(255)); err == nil {
		t.Fatal("unknown mode accepted")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("validation created instance or state", entries, err)
	}
	for _, mutate := range []func(*daemonv1.HelperBootstrap){
		func(w *daemonv1.HelperBootstrap) { w.ClientSecret = []byte("secret") },
		func(w *daemonv1.HelperBootstrap) { w.NativeBridgePath = []byte("/missing") },
		func(w *daemonv1.HelperBootstrap) { w.RuntimeComponents = &daemonv1.RuntimeComponents{} },
		func(w *daemonv1.HelperBootstrap) { w.Settings.StopBudget = durationpb.New(0) },
	} {
		clone := proto.Clone(wire).(*daemonv1.HelperBootstrap)
		mutate(clone)
		if _, err := Validate(clone, ShutdownOnly); err == nil {
			t.Fatal("unsafe shutdown frame accepted")
		}
	}
}
