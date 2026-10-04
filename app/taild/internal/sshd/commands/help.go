package commands

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/sshd/cmdline"
)

var help = Command{
	Name:      "help",
	Summary:   "Show command help.",
	Usage:     "help [COMMAND [SUBCOMMAND]] [--json]",
	Arguments: "COMMAND [SUBCOMMAND]  Optional help topic.",
	Example:   "help template create",
	New:       func() Handler { return &helpHandler{} },
}

type helpHandler struct{}

func (h *helpHandler) Flags(*cmdline.FlagSet) {}

func (h *helpHandler) Run(c *Context, args cmdline.Args) (Result, error) {
	if e := args.NoLiteral(); e != nil {
		return Result{}, e
	}
	if len(args.Positional) > 2 {
		return Result{}, cmdline.Unexpected("help topic")
	}
	return helpFor(c, args.Positional)
}

// helpFor renders general help for an empty path, otherwise the topic named
// by a command and an optional subcommand.
func helpFor(c *Context, path []string) (Result, error) {
	text := generalHelp()
	if len(path) > 0 {
		var configured *config.Config
		if c.Service != nil {
			configured = &c.Service.Config
		}
		var ok bool
		if text, ok = detailedHelp(path, configured); !ok {
			return Result{}, usageReason("unknown command")
		}
	}
	return Result{Data: struct {
		Help string `json:"help"`
	}{text}, Human: text}, nil
}

func generalHelp() string {
	var b strings.Builder
	b.WriteString("silo · VMs on your tailnet\n\nUsage:\n  COMMAND [ARGUMENTS] [OPTIONS]\n\nCommands:\n")
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	listed := append([]Command(nil), all...)
	sort.Slice(listed, func(i, j int) bool { return listed[i].Name < listed[j].Name })
	for _, c := range listed {
		_, _ = fmt.Fprintf(w, "  %s\t%s\n", c.Name, c.Summary)
	}
	_ = w.Flush()
	b.WriteString("\nOptions:\n  -h, --help  Show help.\n  --json      Structured output for supported queries/mutations.\n\nExamples:\n  help create\n  create --name devbox --memory 4GiB\n")
	return b.String()
}

// configurable lets a handler replace an option's documented default with the
// operator's configured value when help runs inside a live service.
type configurable interface {
	Defaults(config.Config) map[string]string
}

func detailedHelp(path []string, configured *config.Config) (string, bool) {
	cmd, ok := lookup(path[0])
	if !ok {
		return "", false
	}
	topic := Topic{Summary: cmd.Summary, Usage: cmd.Usage, Arguments: cmd.Arguments, Example: cmd.Example}
	if len(path) > 1 {
		if len(path) != 2 || cmd.Topics == nil {
			return "", false
		}
		if topic, ok = cmd.Topics(path[1]); !ok {
			return "", false
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\nUsage:\n  %s\n", topic.Summary, topic.Usage)
	if len(cmd.Aliases) > 0 {
		aliases := append([]string(nil), cmd.Aliases...)
		sort.Strings(aliases)
		fmt.Fprintf(&b, "\nAliases:\n  %s\n", strings.Join(aliases, ", "))
	}
	if topic.Arguments != "" {
		fmt.Fprintf(&b, "\nArguments:\n  %s\n", strings.ReplaceAll(topic.Arguments, "\n", "\n  "))
	}
	handler := cmd.New()
	flags := cmdline.NewFlagSet()
	handler.Flags(flags)
	var defaults map[string]string
	if source, ok := handler.(configurable); ok && configured != nil {
		defaults = source.Defaults(*configured)
	}
	options := flags.Options()
	options = append(options, cmdline.Option{Names: []string{"h", "help"}, Help: "Show help."})
	if !cmd.Streaming {
		options = append(options, cmdline.Option{Names: []string{"json"}, Help: "Structured output; does not confirm removal.", Fallback: "false"})
	}
	b.WriteString("\nOptions:\n")
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	for _, o := range options {
		fallback := o.Fallback
		if text, ok := defaults[o.Names[0]]; ok {
			fallback = text
		}
		// Short spellings lead, as in "-h, --help".
		var short, long []string
		for _, n := range o.Names {
			if len(n) == 1 {
				short = append(short, "-"+n)
			} else {
				long = append(long, "--"+n)
			}
		}
		label := strings.Join(append(short, long...), ", ")
		if o.Placeholder != "" {
			label += " " + o.Placeholder
		}
		description := o.Help
		if fallback != "" {
			description += " (default: " + fallback + ")"
		}
		_, _ = fmt.Fprintf(w, "  %s\t%s\n", label, description)
	}
	_ = w.Flush()
	fmt.Fprintf(&b, "\nExamples:\n  %s\n", topic.Example)
	return b.String(), true
}
