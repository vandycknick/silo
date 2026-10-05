package commands

import (
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/sshd/cmdline"
)

var exec = Command{
	Name:      "exec",
	Summary:   "Run a guest command; arguments after -- are literal.",
	Usage:     "exec VM [OPTIONS] -- CMD...",
	Arguments: "VM  Exact name or VM ID.\nCMD...  Guest program and arguments after --.",
	Example:   "exec devbox -- uname -a",
	Streaming: true,
	New:       func() Handler { return &execHandler{q: service.ExecRequest{Env: map[string]string{}}} },
}

type execHandler struct{ q service.ExecRequest }

func (h *execHandler) Flags(f *cmdline.FlagSet) {
	f.String("u", "USER", "Guest user.", &h.q.User).Default("VM default")
	f.String("w", "DIR", "Working directory.", &h.q.Directory).Default("guest default")
	f.Repeat("e", "K=V", "Environment (repeatable).", cmdline.KeyValue(h.q.Env)).Default("none")
	f.Bool("t", "Guest PTY.", &h.q.TTY)
}

func (h *execHandler) Run(c *Context, args cmdline.Args) (Result, error) {
	vm, e := (cmdline.Args{Positional: args.Positional}).One("VM")
	if e != nil {
		return Result{}, e
	}
	if !args.Delimited || len(args.Literal) == 0 {
		return Result{}, cmdline.Missing("CMD (after --)")
	}
	h.q.Program, h.q.Args = args.Literal[0], args.Literal[1:]
	code, e := c.Service.Exec(c, c.Caller, vm, h.q, c.Streams)
	return Result{Exit: code}, e
}
