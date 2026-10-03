package sshd

import (
	"errors"
	"flag"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/units"
)

// flagSet is the strict dialect of the standard flag grammar the SSH command
// line accepts: every flag at most once, unknown flags rejected, and nothing
// positional left over. Error text is never shown; every failure is a usage.
type flagSet struct {
	set     *flag.FlagSet
	command string
}

func newFlagSet(command ...string) flagSet {
	set := flag.NewFlagSet("", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	f := flagSet{set: set}
	if len(command) > 0 {
		f.command = canonicalCommand(command[0])
	}
	return f
}

// option is a flag.Value that accepts exactly one occurrence. The standard
// FlagSet lets the last occurrence win, which hides client mistakes.
type option struct {
	parse   func(string) error
	seen    bool
	boolean bool
	initial string
}

func (o *option) String() string   { return o.initial }
func (o *option) IsBoolFlag() bool { return o.boolean }
func (o *option) Set(v string) error {
	if o.seen {
		return errors.New("repeated flag")
	}
	o.seen = true
	return o.parse(v)
}

// Flag registers a single-use value flag.
func (f flagSet) Flag(name string, parse func(string) error) *option {
	o := &option{parse: parse}
	f.set.Var(o, name, "")
	return o
}

// Alias registers an existing option under a second spelling. Both names
// share one occurrence budget.
func (f flagSet) Alias(name string, o *option) { f.set.Var(o, name, "") }

func (f flagSet) Bool(name string, dst *bool) {
	o := f.Flag(name, func(v string) error {
		b, e := strconv.ParseBool(v)
		*dst = b
		return e
	})
	o.boolean = true
	o.initial = strconv.FormatBool(*dst)
	f.set.Lookup(name).DefValue = o.initial
}

func (f flagSet) String(name string, dst *string) *option {
	return f.Flag(name, func(v string) error { *dst = v; return nil })
}

// Repeat registers a flag that may appear any number of times.
func (f flagSet) Repeat(name string, parse func(string) error) { f.set.Func(name, "", parse) }

// Parse consumes args and requires that every token was a flag or its value.
func (f flagSet) Parse(args []string) error {
	_, e := f.parse(args, false)
	return e
}

// ParsePositionals permits interspersed options without interpreting values as options.
func (f flagSet) ParsePositionals(args []string) ([]string, error) { return f.parse(args, true) }

func usageReason(message string) *authz.Error {
	return &authz.Error{Code: "usage", Message: message, Exit: 2}
}

func (f flagSet) parse(args []string, positional bool) ([]string, error) {
	if err := f.checkMetadata(); err != nil {
		return nil, err
	}
	var rest []string
	for i := 0; i < len(args); i++ {
		token := args[i]
		if !isFlag(token) || token == "-" {
			if !positional {
				return nil, usageReason("unexpected positional argument")
			}
			rest = append(rest, token)
			continue
		}
		name, value, inline := strings.Cut(strings.TrimLeft(token, "-"), "=")
		registered := f.set.Lookup(name)
		if registered == nil {
			return nil, usageReason("unknown option; see command help")
		}
		o, single := registered.Value.(*option)
		if single && o.seen {
			return nil, usageReason("duplicate option --" + name)
		}
		boolean := single && o.boolean
		if !inline {
			if boolean {
				value = "true"
			} else {
				if i+1 == len(args) {
					return nil, usageReason("option --" + name + " requires a value")
				}
				i++
				value = args[i]
			}
		}
		// Never relay stdlib flag errors, which include the supplied value.
		if e := registered.Value.Set(value); e != nil {
			message := "invalid value for --" + name
			if name == "cpus" {
				message += ": expected a positive integer (1..255)"
			}
			return nil, usageReason(message)
		}
	}
	return rest, nil
}

// Check the actual registrations against the specs used by help and the global
// scanner, including alias occurrence budgets. New options cannot silently
// become undocumented or change help-token arity.
func (f flagSet) checkMetadata() error {
	if f.command == "" {
		return nil
	}
	bad := false
	expected := map[string]bool{}
	for _, spec := range metadata[f.command].options {
		if spec.names == "yes" {
			continue
		} // removal confirmation is session-wide
		var first *option
		for _, name := range strings.Split(spec.names, ",") {
			expected[name] = true
			registered := f.set.Lookup(name)
			if registered == nil {
				bad = true
				continue
			}
			boolean := false
			if value, ok := registered.Value.(interface{ IsBoolFlag() bool }); ok {
				boolean = value.IsBoolFlag()
			}
			if boolean != (spec.value == "") {
				bad = true
			}
			if boolean && registered.DefValue != spec.fallback {
				bad = true
			}
			if strings.Contains(spec.names, ",") {
				o, ok := registered.Value.(*option)
				if !ok || first != nil && first != o {
					bad = true
				}
				first = o
			}
		}
	}
	f.set.VisitAll(func(flag *flag.Flag) {
		if !expected[flag.Name] {
			bad = true
		}
	})
	if bad {
		return &authz.Error{Code: "unavailable", Message: "command option metadata inconsistent", Exit: 9}
	}
	return nil
}

func isFlag(token string) bool { return strings.HasPrefix(token, "-") }

// shift takes the leading positional argument.
func shift(args []string) (string, []string, error) {
	if len(args) == 0 || isFlag(args[0]) {
		return "", nil, usage()
	}
	return args[0], args[1:], nil
}

// splitDelimiter separates options from the literal guest command after "--".
func splitDelimiter(args []string) (options, command []string, ok bool) {
	for i, token := range args {
		if token == "--" {
			return args[:i], args[i+1:], true
		}
	}
	return args, nil, false
}

func nonEmpty(dst *string) func(string) error {
	return func(v string) error {
		if v == "" {
			return usage()
		}
		*dst = v
		return nil
	}
}

func principal(dst *identity.Principal) func(string) error {
	return func(v string) error { *dst = identity.Principal(v); return nil }
}

func size(dst *uint64) func(string) error {
	return func(v string) error {
		n, e := units.Bytes(v)
		if e != nil || n == 0 {
			return usage()
		}
		*dst = n
		return nil
	}
}

func count(dst *uint64) func(string) error {
	return func(v string) error {
		n, e := strconv.ParseUint(v, 10, 64)
		if e != nil || n == 0 || n > 255 {
			return usage()
		}
		*dst = n
		return nil
	}
}

func duration(dst *time.Duration) func(string) error {
	return func(v string) (e error) { *dst, e = time.ParseDuration(v); return e }
}

func keyValue(dst map[string]string) func(string) error {
	return func(v string) error {
		k, value, ok := strings.Cut(v, "=")
		if !ok {
			return usage()
		}
		dst[k] = value
		return nil
	}
}
