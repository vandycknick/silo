package commands

import (
	"errors"
	"strings"

	"github.com/vandycknick/silo/app/taild/internal/sshd/cmdline"
)

// all is the whole application in one place, in help order.
var all = []Command{whoami, version, help, ls, show, ops, create, start, restart, stop, rm, set, shell, exec, logs, template, policy}

func lookup(name string) (Command, bool) {
	for _, c := range all {
		if c.Name == name {
			return c, true
		}
		for _, alias := range c.Aliases {
			if alias == name {
				return c, true
			}
		}
	}
	return Command{}, false
}

// flagsOf declares a command's options on a scratch set, for help and arity.
func flagsOf(c Command) *cmdline.FlagSet {
	f := cmdline.NewFlagSet()
	c.New().Flags(f)
	return f
}

// Execute runs one tokenized line: session-wide flags, alias and help
// resolution, option parsing, then the handler. It is the only entry point.
func Execute(c *Context, tokens []string) (Result, error) {
	var declared *cmdline.FlagSet
	for i, t := range tokens {
		if !cmdline.IsFlag(t) {
			if cmd, ok := lookup(t); ok {
				declared = flagsOf(cmd)
			}
			// Route leading options through the same command stream and
			// occurrence budget as options after the verb.
			if i > 0 {
				args := append(append([]string{t}, tokens[:i]...), tokens[i+1:]...)
				tokens = args
			}
			break
		}
	}
	tokens, wantHelp, e := c.sessionFlags(tokens, declared)
	if e != nil {
		return Result{}, e
	}
	if len(tokens) == 0 {
		if wantHelp {
			return helpFor(c, nil)
		}
		return Result{}, usageReason("command required")
	}
	cmd, ok := lookup(tokens[0])
	if !ok {
		return Result{}, Usage()
	}
	if wantHelp {
		path := []string{cmd.Name}
		args, err := flagsOf(cmd).ParseHelp(tokens[1:])
		if err != nil {
			return Result{}, usageReason(err.Error())
		}
		if cmd.Topics != nil && len(args.Positional) > 0 {
			path = append(path, args.Positional[0])
		}
		return helpFor(c, path)
	}
	if c.JSON && cmd.Streaming {
		return Result{}, usageReason("--json is not supported by this command")
	}
	h := cmd.New()
	f := cmdline.NewFlagSet()
	h.Flags(f)
	args, e := f.Parse(tokens[1:])
	if e != nil {
		return Result{}, usageReason(e.Error())
	}
	result, err := h.Run(c, args)
	var positional *cmdline.PositionalError
	if errors.As(err, &positional) {
		return result, usageReason(cmd.Name + ": " + positional.Error() + ". See '" + cmd.Name + " --help'.")
	}
	return result, err
}

// sessionFlags strips the flags every command accepts. Tokens after the
// literal guest delimiter are never interpreted, and a token that is the value
// of a declared option is never mistaken for a session flag.
func (c *Context) sessionFlags(tokens []string, declared *cmdline.FlagSet) ([]string, bool, error) {
	kept := make([]string, 0, len(tokens))
	wantHelp := false
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		switch t {
		case "--":
			return append(kept, tokens[i:]...), wantHelp, nil
		case "--json":
			if c.JSON {
				return nil, false, usageReason("duplicate --json")
			}
			c.JSON = true
		case "-h", "--help":
			wantHelp = true
		default:
			kept = append(kept, t)
			name, _, inline := strings.Cut(strings.TrimLeft(t, "-"), "=")
			if cmdline.IsFlag(t) && !inline && declared != nil && declared.TakesValue(name) && i+1 < len(tokens) {
				i++
				kept = append(kept, tokens[i])
			}
		}
	}
	return kept, wantHelp, nil
}
