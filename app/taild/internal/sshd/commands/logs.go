package commands

import (
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/sshd/cmdline"
	silo "github.com/vandycknick/silo/sdk/go"
)

var logs = Command{
	Name:      "logs",
	Summary:   "Read bounded VM logs.",
	Usage:     "logs VM [--follow] [--stream monitor|serial|exec|network|network-audit] [--output stdout|stderr]",
	Arguments: "VM  Exact name or VM ID.",
	Example:   "logs devbox --stream serial",
	Streaming: true,
	New:       func() Handler { return &logsHandler{} },
}

type logsHandler struct{ q service.LogsRequest }

func (h *logsHandler) Flags(f *cmdline.FlagSet) {
	f.Bool("follow", "Follow output.", &h.q.Follow)
	f.Value("stream", "STREAM", "monitor, serial, exec, network or network-audit.", func(v string) error {
		h.q.Source = silo.MachineLogSource(v)
		// The SDK spells this one with an underscore; the CLI uses a dash.
		if v == "network-audit" {
			h.q.Source = silo.MachineLogNetworkAudit
		}
		return nil
	}).Default(string(service.DefaultLogSource))
	f.Value("output", "OUTPUT", "stdout or stderr; omitted includes both.", func(v string) error { h.q.Output = silo.MachineLogOutput(v); return nil }).Default("all")
}

func (h *logsHandler) Run(c *Context, args cmdline.Args) (Result, error) {
	vm, e := args.One("VM")
	if e != nil {
		return Result{}, e
	}
	return Result{}, c.Service.Logs(c, c.Caller, vm, h.q, c.Streams.Stdout)
}
