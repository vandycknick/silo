package commands

import (
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/sshd/cmdline"
)

// template and policy differ only in document kind.
var (
	template = documentsCommand("template", "Manage YAML templates: ls, show, create, edit, rm, validate.", "SUBCOMMAND  create/edit/validate read one YAML document from stdin.", "one YAML document", "help template create")
	policy   = documentsCommand("policy", "Manage HCL policies: ls, show, create, edit, rm, validate.", "SUBCOMMAND  create/edit/validate read HCL from stdin.", "HCL", "help policy validate")
)

func documentsCommand(kind, summary, arguments, format, example string) Command {
	return Command{
		Name:      kind,
		Summary:   summary,
		Usage:     kind + " ls|show NAME|create NAME|edit NAME|rm NAME|validate [--owner tag:NAME] [--json]; create/edit/validate read " + format + " from stdin",
		Arguments: arguments,
		Example:   example,
		Topics:    documentTopics(kind),
		New:       func() Handler { return &documentsHandler{kind: kind} },
	}
}

func documentTopics(kind string) func(string) (Topic, bool) {
	return func(verb string) (Topic, bool) {
		t := Topic{Summary: "Manage a " + kind + " document.", Example: kind + " " + verb}
		switch verb {
		case "ls", "validate":
			t.Usage = kind + " " + verb + " [OPTIONS]"
		case "show", "create", "edit", "rm":
			t.Usage = kind + " " + verb + " NAME [OPTIONS]"
			t.Arguments = "NAME  Document name in your namespace."
			t.Example += " dev"
		default:
			return Topic{}, false
		}
		if verb == "create" || verb == "edit" || verb == "validate" {
			t.Summary += " Reads one document from stdin."
		}
		return t, true
	}
}

type documentsHandler struct {
	kind  string
	owner identity.Principal
}

func (h *documentsHandler) Flags(f *cmdline.FlagSet) {
	f.Value("owner", "tag:NAME", "Verified owner namespace.", principal(&h.owner)).Default("your principal")
}

func (h *documentsHandler) Run(c *Context, args cmdline.Args) (Result, error) {
	if e := args.NoLiteral(); e != nil {
		return Result{}, e
	}
	if len(args.Positional) == 0 {
		return Result{}, cmdline.Missing("SUBCOMMAND")
	}
	verb, name := args.Positional[0], ""
	switch verb {
	case "ls", "validate":
		if e := (cmdline.Args{Positional: args.Positional[1:]}).None(); e != nil {
			return Result{}, e
		}
	case "show", "create", "edit", "rm":
		var e error
		name, e = (cmdline.Args{Positional: args.Positional[1:]}).One("NAME")
		if e != nil {
			return Result{}, e
		}
	default:
		return Result{}, usageReason(h.kind + ": unknown SUBCOMMAND. See '" + h.kind + " --help'.")
	}
	raw := ""
	switch verb {
	case "create", "edit", "validate":
		action := identity.TemplateManage
		if verb == "validate" {
			action = identity.Read
		}
		data, e := c.Document(action, service.DocumentLimit)
		if e != nil {
			return Result{}, e
		}
		raw = string(data)
	}
	docs, e := c.Service.Documents(c, c.Caller, h.kind, verb, name, h.owner, raw)
	if e != nil {
		return Result{}, e
	}
	return Result{Data: docs, Human: renderDocuments(verb, docs)}, nil
}
