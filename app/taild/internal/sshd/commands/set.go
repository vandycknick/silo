package commands

import (
	"strconv"
	"strings"

	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/sshd/cmdline"
)

var set = Command{
	Name:      "set",
	Summary:   "Update a stopped VM.",
	Usage:     "set VM name=NAME|cpus=N|memory=SIZE|disk=SIZE... [--json]",
	Arguments: "VM  Exact name or VM ID.\nKEY=VALUE  name, cpus, memory or disk. Sizes are binary.",
	Example:   "set devbox memory=8gb disk=16GiB",
	New:       func() Handler { return &setHandler{} },
}

type setHandler struct{ q service.SetRequest }

func (h *setHandler) Flags(*cmdline.FlagSet) {}

func (h *setHandler) Run(c *Context, args cmdline.Args) (Result, error) {
	if e := args.NoLiteral(); e != nil {
		return Result{}, e
	}
	if len(args.Positional) == 0 {
		return Result{}, cmdline.Missing("VM")
	}
	if len(args.Positional) == 1 {
		return Result{}, cmdline.Missing("KEY=VALUE")
	}
	vm := args.Positional[0]
	seen := map[string]bool{}
	for _, arg := range args.Positional[1:] {
		k, v, ok := strings.Cut(arg, "=")
		if !ok {
			return Result{}, usageReason("set expects KEY=VALUE")
		}
		if seen[k] {
			return Result{}, usageReason("duplicate setting")
		}
		seen[k] = true
		switch k {
		case "name":
			h.q.Name = &v
		case "cpus":
			n, e := strconv.ParseUint(v, 10, 8)
			if e != nil || n == 0 {
				return Result{}, usageReason("invalid cpus setting: expected a positive integer (1..255)")
			}
			cpus := uint8(n)
			h.q.CPUs = &cpus
		case "memory":
			h.q.MemoryText = &v
		case "disk":
			h.q.DiskText = &v
		default:
			return Result{}, usageReason("unknown setting; expected name, cpus, memory or disk")
		}
	}
	return c.Await(c.Service.Set(c, c.Caller, vm, h.q))
}
