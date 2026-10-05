package commands

import "github.com/vandycknick/silo/app/taild/internal/sshd/cmdline"

var shell = Command{
	Name:      "shell",
	Summary:   "Open a guest shell (requires SSH PTY).",
	Usage:     "shell VM [OPTIONS]",
	Arguments: "VM  Exact name or VM ID.",
	Example:   "shell devbox -u root",
	Aliases:   []string{"ssh"},
	Streaming: true,
	New:       func() Handler { return &shellHandler{} },
}

type shellHandler struct{ user string }

func (h *shellHandler) Flags(f *cmdline.FlagSet) {
	f.String("u", "USER", "Guest user.", &h.user).Default("VM default")
}

func (h *shellHandler) Run(c *Context, args cmdline.Args) (Result, error) {
	vm, e := args.One("VM")
	if e != nil {
		return Result{}, e
	}
	code, e := c.Service.Shell(c, c.Caller, vm, h.user, c.Streams)
	return Result{Exit: code}, e
}
