package commands

import (
	"github.com/vandycknick/silo/app/taild/internal/sshd/cmdline"
	"github.com/vandycknick/silo/app/taild/internal/state"
	silo "github.com/vandycknick/silo/sdk/go"
)

var show = Command{
	Name:      "show",
	Summary:   "Inspect a VM.",
	Usage:     "show VM [OPTIONS]",
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
	if vm.ApprovalURL != "" && c.Streams.ApprovalShown != nil {
		c.Streams.ApprovalShown(vm.ID, vm.ApprovalURL)
	}
	human := renderShow(vm)
	if vm.State == silo.MachineStatusRunning {
		human += connectionHints(safeText(c.Service.Config.Tailnet.Hostname), safeText(vm.Name), safeText(vm.DefaultUser), safeText(vm.Node), vm.NodeState == state.Enrolled)
	}
	return Result{Data: vm, Human: human}, nil
}
