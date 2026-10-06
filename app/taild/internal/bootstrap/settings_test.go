package bootstrap

import (
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/config"
	daemonv1 "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

func resolvedSettings() *daemonv1.TailscaleSettings {
	return &daemonv1.TailscaleSettings{
		Hostname: "resolved-host", Tag: "tag:resolved", ControlUrl: "https://control.example.test",
		EnrollmentMode: daemonv1.EnrollmentMode_ENROLLMENT_MODE_INTERACTIVE,
		DefaultImage:   "registry.example.test/image:resolved", AllowedRegistries: []string{"registry.example.test"},
		Defaults:       &daemonv1.ResourceDefaults{Cpus: 1, MemoryBytes: 256 << 20, DiskBytes: 1 << 30},
		Ceilings:       &daemonv1.ResourceCeilings{Cpus: 3, MemoryBytes: 1 << 30, DiskBytes: 4 << 30, VmsPerPrincipal: 2},
		SessionsGlobal: 4, SessionsPerPeer: 2, DiskReserveBytes: 1234,
		StopBudget: durationpb.New(3 * time.Second), ShutdownMargin: durationpb.New(100 * time.Millisecond),
	}
}

func TestResolvedSettingsRejectInvalidLimits(t *testing.T) {
	c := config.Config{Home: "/resolved/home"}
	for _, mutate := range []func(*daemonv1.TailscaleSettings){
		func(s *daemonv1.TailscaleSettings) {
			s.EnrollmentMode = daemonv1.EnrollmentMode_ENROLLMENT_MODE_UNSPECIFIED
		},
		func(s *daemonv1.TailscaleSettings) { s.Defaults = nil },
		func(s *daemonv1.TailscaleSettings) { s.SessionsGlobal = 0 },
		func(s *daemonv1.TailscaleSettings) { s.StopBudget = nil },
		func(s *daemonv1.TailscaleSettings) { s.Defaults.Cpus = s.Ceilings.Cpus + 1 },
	} {
		s := resolvedSettings()
		mutate(s)
		if err := settings(&c, s); err == nil {
			t.Fatal("invalid bootstrap settings accepted")
		}
	}
}
