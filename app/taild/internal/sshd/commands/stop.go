package commands

import (
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/sshd/cmdline"
)

var stop = Command{
	Name:      "stop",
	Summary:   "Stop a VM.",
	Usage:     "stop VM [OPTIONS]",
	Arguments: "VM  Exact name or VM ID.",
	Example:   "stop devbox --timeout 30s",
	New:       func() Handler { return &stopHandler{} },
}

type stopHandler struct{ q service.StopRequest }

func (h *stopHandler) Flags(f *cmdline.FlagSet) {
	f.Bool("force", "Force shutdown.", &h.q.Force)
	f.Value("timeout", "DURATION", "Shutdown deadline.", cmdline.Duration(&h.q.Timeout)).Default("configured")
}

func (h *stopHandler) Run(c *Context, args cmdline.Args) (Result, error) {
	vm, e := args.One("VM")
	if e != nil {
		return Result{}, e
	}
	return c.Await(c.Service.Stop(c, c.Caller, vm, h.q))
}
