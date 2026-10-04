package commands

import "github.com/vandycknick/silo/app/taild/internal/sshd/cmdline"

var ls = Command{
	Name:    "ls",
	Summary: "List your VMs.",
	Usage:   "ls [--json]",
	Example: "ls",
	Aliases: []string{"list"},
	New:     func() Handler { return &lsHandler{} },
}

type lsHandler struct{}

func (h *lsHandler) Flags(*cmdline.FlagSet) {}

func (h *lsHandler) Run(c *Context, args cmdline.Args) (Result, error) {
	if e := args.None(); e != nil {
		return Result{}, e
	}
	vms, e := c.Service.List(c, c.Caller.Peer)
	if e != nil {
		return Result{}, e
	}
	return Result{Data: vms, Human: renderList(vms)}, nil
}
