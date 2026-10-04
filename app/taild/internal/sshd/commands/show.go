package commands

import "github.com/vandycknick/silo/app/taild/internal/sshd/cmdline"

var show = Command{
	Name:      "show",
	Summary:   "Inspect a VM.",
	Usage:     "show VM [--json]",
	Arguments: "VM  Exact name or VM ID.",
	Example:   "show devbox",
	Aliases:   []string{"status"},
	New:       func() Handler { return &showHandler{} },
}

type showHandler struct{}

func (h *showHandler) Flags(*cmdline.FlagSet) {}

func (h *showHandler) Run(c *Context, args cmdline.Args) (Result, error) {
	ref, e := args.One("VM")
	if e != nil {
		return Result{}, e
	}
	vm, e := c.Service.Show(c, c.Caller.Peer, ref)
	if e != nil {
		return Result{}, e
	}
	return Result{Data: vm, Human: renderShow(vm)}, nil
}
