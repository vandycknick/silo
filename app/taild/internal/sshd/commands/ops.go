package commands

import (
	"github.com/vandycknick/silo/app/taild/internal/sshd/cmdline"
	"strings"
)

var ops = Command{
	Name:        "ops",
	Summary:     "List operations or inspect one operation.",
	Usage:       "ops [COMMAND] [OPTIONS]",
	Arguments:   "COMMAND  Omit to list operations, or use show to inspect one.",
	Subcommands: []string{"show"},
	Example:     "ops",
	Topics: func(sub string) (Topic, bool) {
		if sub != "show" {
			return Topic{}, false
		}
		return Topic{
			Summary:   "Inspect an operation owned by your principal.",
			Usage:     "ops show OPERATION_ID [OPTIONS]",
			Arguments: "OPERATION_ID  The op_ULID returned by a command.",
			Example:   "ops show op_01ARZ3NDEKTSV4RRFFQ69G5FAV --json",
		}, true
	},
	New: func() Handler { return &opsHandler{} },
}

type opsHandler struct{}

func (h *opsHandler) Flags(*cmdline.FlagSet) {}

func (h *opsHandler) Run(c *Context, args cmdline.Args) (Result, error) {
	id := ""
	if e := args.NoLiteral(); e != nil {
		return Result{}, e
	}
	switch {
	case len(args.Positional) == 0:
	case args.Positional[0] == "show":
		var e error
		id, e = (cmdline.Args{Positional: args.Positional[1:]}).One("OPERATION_ID")
		if e != nil {
			return Result{}, e
		}
	default:
		return Result{}, usageReason("ops: unknown SUBCOMMAND. See 'ops --help'.")
	}
	ops, e := c.Service.Ops(c.Caller.Peer, id)
	if e != nil {
		return Result{}, e
	}
	human := renderOps(ops)
	if id != "" {
		for _, op := range ops {
			if op.Error != nil {
				human += "\nError: " + op.Error.Message + "\n"
			}
			if op.Finished == nil {
				for _, line := range op.Progress {
					if url, ok := strings.CutPrefix(line, "approve: "); ok {
						human += "\nLogin\n  " + url + "\n"
					}
				}
			}
		}
	}
	return Result{Data: ops, Human: human}, nil
}
