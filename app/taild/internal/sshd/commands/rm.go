package commands

import (
	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/sshd/cmdline"
)

var rm = Command{
	Name:      "rm",
	Summary:   "Remove a VM after confirmation.",
	Usage:     "rm VM [--force] [--yes] [--json]",
	Arguments: "VM  Exact name or VM ID.",
	Example:   "rm devbox --yes",
	New:       func() Handler { return &rmHandler{} },
}

type rmHandler struct {
	q   service.RemoveRequest
	yes bool
}

func (h *rmHandler) Flags(f *cmdline.FlagSet) {
	f.Bool("force", "Stop a running VM first.", &h.q.Force)
	f.Bool("yes", "Bypass [y/N] confirmation.", &h.yes)
}

func (h *rmHandler) Run(c *Context, args cmdline.Args) (Result, error) {
	vm, e := args.One("VM")
	if e != nil {
		return Result{}, e
	}
	target, e := c.Service.PreflightRemove(c, c.Caller, vm, h.q.Force)
	if e != nil {
		return Result{}, e
	}
	h.q.Confirmed = h.yes || c.Confirm(target)
	if !h.q.Confirmed || c.Err() != nil {
		return Result{}, &authz.Error{Code: "cancelled", Message: "removal cancelled", Exit: 2}
	}
	return c.Await(c.Service.Remove(c, c.Caller, target.ID, h.q))
}
