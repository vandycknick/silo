package supervision

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

func SystemState(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "systemctl", "is-system-running").Output()
	if ctx.Err() != nil {
		return "", errors.New("host shutdown state unknown; no VMs stopped")
	}
	value := strings.TrimSpace(string(out))
	// systemctl deliberately exits nonzero for stopping and degraded.
	switch value {
	case "stopping", "running", "degraded", "starting", "initializing", "maintenance", "offline":
		return value, nil
	default:
		return "", errors.New("host shutdown state unknown; no VMs stopped")
	}
}
