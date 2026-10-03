package sshd

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/service"
	silo "github.com/vandycknick/silo/sdk/go"
)

func usage() *authz.Error {
	return &authz.Error{Code: "usage", Message: "invalid command arguments; see help", Exit: 2}
}

// invocation is one authenticated command line and the session it runs in.
type invocation struct {
	ctx     context.Context
	service *service.Service
	caller  service.Caller
	streams service.IO
	json    bool
	yes     bool
	help    bool
}

// reply is a command's outcome. exit carries guest or stream exit codes and is
// zero for daemon-owned commands; failures travel as errors, which the
// dispatcher categorizes. data may accompany an error, as a failed operation.
type reply struct {
	data  any
	human string
	exit  int
}

// handler parses its arguments, calls the domain, and renders the result.
type handler func(iv *invocation, args []string) (reply, error)

type command struct {
	usage string
	run   handler
}

var aliases = map[string]string{"new": "create", "list": "ls", "status": "show", "ssh": "shell"}

var commands = map[string]command{
	"whoami":   {"whoami [--json]", runWhoAmI},
	"version":  {"version [--json]", runVersion},
	"ls":       {"ls [--json]", runList},
	"show":     {"show VM [--json]", runShow},
	"ops":      {"ops [show op_ULID] [--json]", runOps},
	"create":   {"create [IMAGE] [-n/--name NAME] [OPTIONS]", runCreate},
	"start":    {"start VM [--json]", vmOperation((*service.Service).Start)},
	"restart":  {"restart VM [--json]", vmOperation((*service.Service).Restart)},
	"reauth":   {"reauth VM [--json] (stopped VM; requires vm.start and vm.stop)", vmOperation((*service.Service).Reauth)},
	"stop":     {"stop VM [--force] [--timeout DURATION] [--json]", runStop},
	"rm":       {"rm VM [--force] [--yes] [--json]", runRemove},
	"set":      {"set VM name=NAME|cpus=N|memory=SIZE|disk=SIZE... [--json]", runSet},
	"shell":    {"shell VM [-u USER] (requires ssh -t)", runShell},
	"exec":     {"exec VM [-u USER] [-w DIR] [-e K=V]... [-t] -- CMD...", runExec},
	"logs":     {"logs VM [--follow] [--stream monitor|serial|exec|network|network-audit] [--output stdout|stderr]", runLogs},
	"template": {"template ls|show NAME|create NAME|edit NAME|rm NAME|validate [--owner tag:NAME] [--json]; create/edit/validate read one YAML document from stdin", documents("template")},
	"policy":   {"policy ls|show NAME|create NAME|edit NAME|rm NAME|validate [--owner tag:NAME] [--json]; create/edit/validate read HCL from stdin", documents("policy")},
}

// help reads the table it is listed in, so it registers after the table.
func init() { commands["help"] = command{"help [COMMAND [SUBCOMMAND]] [--json]", runHelp} }

func commandHelp(name string) (string, bool) {
	return detailedHelp(strings.Fields(name))
}

func runHelp(iv *invocation, args []string) (reply, error) {
	text := generalHelp()
	switch len(args) {
	case 0:
	case 1, 2:
		var ok bool
		if iv.service != nil {
			text, ok = detailedHelp(args, iv.service.Config)
		} else {
			text, ok = detailedHelp(args)
		}
		if !ok {
			return reply{}, &authz.Error{Code: "usage", Message: "unknown command", Exit: 2}
		}
	default:
		return reply{}, usage()
	}
	return reply{data: struct {
		Help string `json:"help"`
	}{text}, human: text}, nil
}

func runVersion(iv *invocation, args []string) (reply, error) {
	if len(args) != 0 {
		return reply{}, usage()
	}
	v := iv.service.Versions()
	return reply{data: v, human: renderVersion(v)}, nil
}

func runWhoAmI(iv *invocation, args []string) (reply, error) {
	if len(args) != 0 {
		return reply{}, usage()
	}
	who, e := iv.service.WhoAmI(iv.caller.Peer)
	if e != nil {
		return reply{}, e
	}
	return reply{data: who, human: renderWhoAmI(iv.service.Capability, who)}, nil
}

func runList(iv *invocation, args []string) (reply, error) {
	if len(args) != 0 {
		return reply{}, usage()
	}
	vms, e := iv.service.List(iv.ctx, iv.caller.Peer)
	if e != nil {
		return reply{}, e
	}
	return reply{data: vms, human: renderList(vms)}, nil
}

func runShow(iv *invocation, args []string) (reply, error) {
	if len(args) != 1 {
		return reply{}, usage()
	}
	vm, e := iv.service.Show(iv.ctx, iv.caller.Peer, args[0])
	if e != nil {
		return reply{}, e
	}
	return reply{data: vm, human: renderShow(vm)}, nil
}

func runOps(iv *invocation, args []string) (reply, error) {
	id := ""
	switch {
	case len(args) == 0:
	case len(args) == 2 && args[0] == "show":
		id = args[1]
	default:
		return reply{}, usage()
	}
	ops, e := iv.service.Ops(iv.caller.Peer, id)
	if e != nil {
		return reply{}, e
	}
	return reply{data: ops, human: renderOps(ops)}, nil
}

func runCreate(iv *invocation, args []string) (reply, error) {
	q := service.CreateRequest{Labels: map[string]string{}}
	f := newFlagSet("create")
	f.Alias("n", f.Flag("name", func(value string) error {
		if !config.ValidName(value) {
			return usage()
		}
		q.Name = value
		return nil
	}))
	image := f.Flag("image", nonEmpty(&q.Image))
	f.Flag("template", nonEmpty(&q.Template))
	f.Flag("policy", nonEmpty(&q.PolicyRef))
	f.Flag("owner", principal(&q.Owner))
	f.Flag("cpus", count(&q.CPUs))
	f.Flag("memory", nonEmpty(&q.MemoryText))
	f.Alias("disk-size", f.Flag("disk", nonEmpty(&q.DiskText)))
	f.Bool("no-tailnet", &q.NoTailnet)
	f.Bool("no-start", &q.NoStart)
	f.Flag("provision-user", func(v string) error {
		u, e := silo.ParseGuestUser(v)
		q.GuestUser = &u
		return e
	})
	userdata := f.String("userdata", &q.Userdata)
	f.Repeat("label", func(v string) error {
		k, value, ok := strings.Cut(v, "=")
		if _, dup := q.Labels[k]; !ok || dup {
			return usage()
		}
		q.Labels[k] = value
		return nil
	})
	positionals, e := f.ParsePositionals(args)
	if e != nil {
		return reply{}, e
	}
	if len(positionals) > 1 {
		return reply{}, usageReason("unexpected positional argument: create accepts one IMAGE")
	}
	if len(positionals) == 1 {
		if image.seen {
			return reply{}, usageReason("IMAGE and --image cannot be supplied together")
		}
		if e := image.Set(positionals[0]); e != nil {
			return reply{}, usageReason("invalid IMAGE")
		}
	}
	// Parsing stays pure; the one flag that reads the session does so after.
	q.UserdataSet = userdata.seen
	if q.UserdataSet && q.Userdata == "-" {
		data, e := iv.document(identity.Create, 16384)
		if e != nil {
			return reply{}, e
		}
		q.Userdata = string(data)
	}
	return iv.await(iv.service.Create(iv.ctx, iv.caller, q))
}

// vmOperation adapts the single-argument mutations, which share a grammar.
func vmOperation(run func(*service.Service, context.Context, service.Caller, string) (jobs.Operation, error)) handler {
	return func(iv *invocation, args []string) (reply, error) {
		if len(args) != 1 {
			return reply{}, usage()
		}
		return iv.await(run(iv.service, iv.ctx, iv.caller, args[0]))
	}
}

func runStop(iv *invocation, args []string) (reply, error) {
	vm, args, e := shift(args)
	if e != nil {
		return reply{}, e
	}
	var q service.StopRequest
	f := newFlagSet("stop")
	f.Bool("force", &q.Force)
	f.Flag("timeout", duration(&q.Timeout))
	if e := f.Parse(args); e != nil {
		return reply{}, e
	}
	return iv.await(iv.service.Stop(iv.ctx, iv.caller, vm, q))
}

func runRemove(iv *invocation, args []string) (reply, error) {
	vm, args, e := shift(args)
	if e != nil {
		return reply{}, e
	}
	q := service.RemoveRequest{Confirmed: iv.yes}
	f := newFlagSet("rm")
	f.Bool("force", &q.Force)
	if e := f.Parse(args); e != nil {
		return reply{}, e
	}
	target, e := iv.service.PreflightRemove(iv.ctx, iv.caller, vm, q.Force)
	if e != nil {
		return reply{}, e
	}
	if !q.Confirmed {
		q.Confirmed = confirmRemoval(iv.ctx, iv.streams, target)
	}
	if !q.Confirmed || iv.ctx.Err() != nil {
		return reply{}, &authz.Error{Code: "cancelled", Message: "removal cancelled", Exit: 2}
	}
	return iv.await(iv.service.Remove(iv.ctx, iv.caller, target.ID, q))
}

func runSet(iv *invocation, args []string) (reply, error) {
	vm, args, e := shift(args)
	if e != nil || len(args) == 0 {
		return reply{}, usage()
	}
	var q service.SetRequest
	seen := map[string]bool{}
	for _, arg := range args {
		k, v, ok := strings.Cut(arg, "=")
		if !ok || seen[k] {
			if seen[k] {
				return reply{}, usageReason("duplicate setting")
			}
			return reply{}, usageReason("set expects KEY=VALUE")
		}
		seen[k] = true
		switch k {
		case "name":
			q.Name = &v
		case "cpus":
			n, e := strconv.ParseUint(v, 10, 8)
			if e != nil || n == 0 {
				return reply{}, usageReason("invalid cpus setting: expected a positive integer (1..255)")
			}
			cpus := uint8(n)
			q.CPUs = &cpus
		case "memory", "disk":
			if k == "memory" {
				q.MemoryText = &v
			} else {
				q.DiskText = &v
			}
		default:
			return reply{}, usageReason("unknown setting; expected name, cpus, memory or disk")
		}
	}
	return iv.await(iv.service.Set(iv.ctx, iv.caller, vm, q))
}

func runShell(iv *invocation, args []string) (reply, error) {
	vm, args, e := shift(args)
	if e != nil {
		return reply{}, e
	}
	user := ""
	f := newFlagSet("shell")
	f.String("u", &user)
	if e := f.Parse(args); e != nil {
		return reply{}, e
	}
	code, e := iv.service.Shell(iv.ctx, iv.caller, vm, user, iv.streams)
	return reply{exit: code}, e
}

func runExec(iv *invocation, args []string) (reply, error) {
	vm, args, e := shift(args)
	if e != nil {
		return reply{}, e
	}
	options, guest, ok := splitDelimiter(args)
	if !ok || len(guest) == 0 {
		return reply{}, usage()
	}
	q := service.ExecRequest{Env: map[string]string{}, Program: guest[0], Args: guest[1:]}
	f := newFlagSet("exec")
	f.String("u", &q.User)
	f.String("w", &q.Directory)
	f.Bool("t", &q.TTY)
	f.Repeat("e", keyValue(q.Env))
	if e := f.Parse(options); e != nil {
		return reply{}, e
	}
	code, e := iv.service.Exec(iv.ctx, iv.caller, vm, q, iv.streams)
	return reply{exit: code}, e
}

func runLogs(iv *invocation, args []string) (reply, error) {
	vm, args, e := shift(args)
	if e != nil {
		return reply{}, e
	}
	var q service.LogsRequest
	f := newFlagSet("logs")
	f.Bool("follow", &q.Follow)
	f.Flag("stream", func(v string) error {
		q.Source = silo.MachineLogSource(v)
		// The SDK spells this one with an underscore; the CLI uses a dash.
		if v == "network-audit" {
			q.Source = silo.MachineLogNetworkAudit
		}
		return nil
	})
	f.Flag("output", func(v string) error { q.Output = silo.MachineLogOutput(v); return nil })
	if e := f.Parse(args); e != nil {
		return reply{}, e
	}
	return reply{}, iv.service.Logs(iv.ctx, iv.caller, vm, q, iv.streams.Stdout)
}

// documents serves template and policy, which differ only in document kind.
func documents(kind string) handler {
	return func(iv *invocation, args []string) (reply, error) {
		verb, args, e := shift(args)
		if e != nil {
			return reply{}, e
		}
		name := ""
		switch verb {
		case "ls", "validate":
		case "show", "create", "edit", "rm":
			if name, args, e = shift(args); e != nil {
				return reply{}, e
			}
		default:
			return reply{}, usage()
		}
		var owner identity.Principal
		f := newFlagSet(kind)
		f.Flag("owner", principal(&owner))
		if e := f.Parse(args); e != nil {
			return reply{}, e
		}
		raw := ""
		switch verb {
		case "create", "edit", "validate":
			action := identity.TemplateManage
			if verb == "validate" {
				action = identity.Read
			}
			data, e := iv.document(action, service.DocumentLimit)
			if e != nil {
				return reply{}, e
			}
			raw = string(data)
		}
		docs, e := iv.service.Documents(iv.ctx, iv.caller, kind, verb, name, owner, raw)
		if e != nil {
			return reply{}, e
		}
		return reply{data: docs, human: renderDocuments(verb, docs)}, nil
	}
}

// document reads one bounded document from the session input. The peer must
// hold the action before the daemon consumes any of its bytes.
func (iv *invocation) document(action identity.Action, limit int) ([]byte, error) {
	if e := iv.service.Authorize(iv.caller.Peer, action, nil); e != nil {
		return nil, e
	}
	return documentInput(iv.ctx, iv.streams, limit)
}

// await relays operation progress to the human stream until it finishes. The
// subscription belongs to this session; the operation belongs to jobs and
// keeps running if the session disconnects.
func (iv *invocation) await(op jobs.Operation, err error) (reply, error) {
	if err != nil {
		return reply{}, err
	}
	out := humanOutput(iv.streams)
	reported := 0
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		current, changed, e := iv.service.Jobs.Observe(iv.caller.Peer, op.ID)
		if e != nil {
			return reply{}, e
		}
		if reported > len(current.Progress) {
			reported = 0
		}
		for _, line := range current.Progress[reported:] {
			if _, e := fmt.Fprintln(out, line); e != nil {
				return reply{}, e
			}
		}
		reported = len(current.Progress)
		if current.Finished != nil {
			if current.Error != nil {
				return reply{data: current}, current.Error
			}
			message := current.Kind + " succeeded\n"
			if current.Kind == "create" {
				message = "create " + current.VM + " succeeded\n"
			}
			return reply{data: current, human: message}, nil
		}
		select {
		case <-iv.ctx.Done():
			return reply{data: op}, &authz.Error{Code: "disconnected", Message: "observer closed; operation continues", Exit: 255}
		case <-changed:
		case <-ticker.C:
			p, e := iv.caller.Fresh(iv.ctx)
			if e != nil || !p.Owns(current.Principal) {
				return reply{}, &authz.Error{Code: "forbidden", Message: "operation observer authorization lost", Exit: 4}
			}
			iv.caller.Peer = p
		}
	}
}
