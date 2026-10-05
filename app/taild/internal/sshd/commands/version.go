package commands

import "github.com/vandycknick/silo/app/taild/internal/sshd/cmdline"

var version = Command{
	Name:    "version",
	Summary: "Show daemon, SDK and runtime versions.",
	Usage:   "version [OPTIONS]",
	Example: "version",
	New:     func() Handler { return &versionHandler{} },
}

type versionHandler struct{}

func (h *versionHandler) Flags(*cmdline.FlagSet) {}

func (h *versionHandler) Run(c *Context, args cmdline.Args) (Result, error) {
	if e := args.None(); e != nil {
		return Result{}, e
	}
	v := c.Service.Versions()
	return Result{Data: v, Human: renderVersion(v)}, nil
}
