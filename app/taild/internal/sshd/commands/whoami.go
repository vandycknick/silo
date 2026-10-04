package commands

import "github.com/vandycknick/silo/app/taild/internal/sshd/cmdline"

var whoami = Command{
	Name:    "whoami",
	Summary: "Show your verified user and node.",
	Usage:   "whoami [--json]",
	Example: "whoami --json",
	New:     func() Handler { return &whoamiHandler{} },
}

type whoamiHandler struct{}

func (h *whoamiHandler) Flags(*cmdline.FlagSet) {}

func (h *whoamiHandler) Run(c *Context, args cmdline.Args) (Result, error) {
	if e := args.None(); e != nil {
		return Result{}, e
	}
	who, e := c.Service.WhoAmI(c.Caller.Peer)
	if e != nil {
		return Result{}, e
	}
	return Result{Data: who, Human: renderWhoAmI(who)}, nil
}
