package commands

import (
	"context"

	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/sshd/cmdline"
)

// start, restart and reauth share one grammar: a VM and nothing else.
var (
	start = Command{
		Name:      "start",
		Summary:   "Start a stopped VM.",
		Usage:     "start VM [--json]",
		Arguments: "VM  Exact name or VM ID.",
		Example:   "start devbox",
		New:       func() Handler { return &vmHandler{(*service.Service).Start} },
	}
	restart = Command{
		Name:      "restart",
		Summary:   "Restart a VM.",
		Usage:     "restart VM [--json]",
		Arguments: "VM  Exact name or VM ID.",
		Example:   "restart devbox",
		New:       func() Handler { return &vmHandler{(*service.Service).Restart} },
	}
	reauth = Command{
		Name:      "reauth",
		Summary:   "Reauthenticate a stopped VM (requires start and stop grants).",
		Usage:     "reauth VM [--json] (stopped VM; requires vm.start and vm.stop)",
		Arguments: "VM  Exact name or VM ID.",
		Example:   "reauth devbox",
		New:       func() Handler { return &vmHandler{(*service.Service).Reauth} },
	}
)

type vmHandler struct {
	run func(*service.Service, context.Context, service.Caller, string) (jobs.Operation, error)
}

func (h *vmHandler) Flags(*cmdline.FlagSet) {}

func (h *vmHandler) Run(c *Context, args cmdline.Args) (Result, error) {
	vm, e := args.One("VM")
	if e != nil {
		return Result{}, e
	}
	return c.Await(h.run(c.Service, c, c.Caller, vm))
}
