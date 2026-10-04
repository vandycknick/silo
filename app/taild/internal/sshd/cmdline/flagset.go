// Package cmdline parses the strict option grammar of the SSH command line.
// It knows nothing about VMs: commands declare their options once, and the
// same declaration drives parsing, help text and option arity.
package cmdline

import (
	"errors"
	"strconv"
	"strings"
)

// Option is one declared flag. An option accepts exactly one occurrence
// unless declared with Repeat; the standard library lets the last win, which
// hides client mistakes.
type Option struct {
	// Names holds the canonical spelling first, then aliases, without dashes.
	Names       []string
	Placeholder string // empty for a boolean
	Help        string
	Fallback    string // shown by help as the default; never applied by Parse
	parse       func(string) error
	seen        bool
	repeat      bool
}

// Seen reports whether the option appeared on the command line.
func (o *Option) Seen() bool { return o.seen }

// Default records descriptive help text only. It does not initialize the flag
// destination or apply a default during parsing.
func (o *Option) Default(text string) *Option {
	o.Fallback = text
	return o
}

func (o *Option) boolean() bool { return o.Placeholder == "" }

func (o *Option) set(value string) error {
	if o.seen && !o.repeat {
		return errors.New("repeated option")
	}
	o.seen = true
	return o.parse(value)
}

// FlagSet is a command's declared options in declaration order.
type FlagSet struct {
	options []*Option
	byName  map[string]*Option
}

func NewFlagSet() *FlagSet { return &FlagSet{byName: map[string]*Option{}} }

func (f *FlagSet) add(name, placeholder, help string, parse func(string) error) *Option {
	o := &Option{Names: []string{name}, Placeholder: placeholder, Help: help, parse: parse}
	f.options = append(f.options, o)
	f.byName[name] = o
	return o
}

// Bool declares a flag that takes no value. "--name=false" is still accepted.
func (f *FlagSet) Bool(name, help string, dst *bool) *Option {
	o := f.add(name, "", help, func(v string) error {
		b, e := strconv.ParseBool(v)
		*dst = b
		return e
	})
	return o.Default(strconv.FormatBool(*dst))
}

func (f *FlagSet) String(name, placeholder, help string, dst *string) *Option {
	return f.add(name, placeholder, help, func(v string) error { *dst = v; return nil })
}

// Value declares a flag whose value goes through parse.
func (f *FlagSet) Value(name, placeholder, help string, parse func(string) error) *Option {
	return f.add(name, placeholder, help, parse)
}

// Repeat declares a flag that may appear any number of times.
func (f *FlagSet) Repeat(name, placeholder, help string, parse func(string) error) *Option {
	o := f.add(name, placeholder, help, parse)
	o.repeat = true
	return o
}

// Alias registers an existing option under a second spelling. Both names
// share one occurrence budget.
func (f *FlagSet) Alias(name string, o *Option) {
	o.Names = append(o.Names, name)
	f.byName[name] = o
}

// TakesValue reports whether the named option consumes the following token,
// which a scanner needs before it can tell flags from values.
func (f *FlagSet) TakesValue(name string) bool {
	o, ok := f.byName[name]
	return ok && !o.boolean()
}

// Options returns the declarations in order, for help rendering.
func (f *FlagSet) Options() []Option {
	out := make([]Option, 0, len(f.options))
	for _, o := range f.options {
		out = append(out, *o)
	}
	return out
}

// Parse interprets args. Positionals may be interspersed with options; every
// token after a bare "--" is literal. Unknown options, repeats, missing values
// and parser rejections are errors that never echo the supplied value.
func (f *FlagSet) Parse(args []string) (Args, error) {
	return f.parse(args, true)
}

// ParseHelp uses the same option arity and positional grammar without applying
// option values. Help must not require valid resources or perform value work.
func (f *FlagSet) ParseHelp(args []string) (Args, error) {
	return f.parse(args, false)
}

func (f *FlagSet) parse(args []string, apply bool) (Args, error) {
	var parsed Args
	for i := 0; i < len(args); i++ {
		token := args[i]
		if token == "--" {
			parsed.Delimited = true
			parsed.Literal = args[i+1:]
			return parsed, nil
		}
		if !IsFlag(token) || token == "-" {
			parsed.Positional = append(parsed.Positional, token)
			continue
		}
		name, value, inline := strings.Cut(strings.TrimLeft(token, "-"), "=")
		o := f.byName[name]
		if o == nil {
			return parsed, errors.New("unknown option; see command help")
		}
		if o.seen && !o.repeat {
			return parsed, errors.New("duplicate option --" + name)
		}
		if !inline {
			if o.boolean() {
				value = "true"
			} else {
				if i+1 == len(args) {
					return parsed, errors.New("option --" + name + " requires a value")
				}
				i++
				value = args[i]
			}
		}
		if !apply {
			o.seen = true
			continue
		}
		if e := o.set(value); e != nil {
			var reason *ValueError
			if errors.As(e, &reason) {
				return parsed, errors.New("invalid value for --" + name + ": " + reason.Reason)
			}
			return parsed, errors.New("invalid value for --" + name)
		}
	}
	return parsed, nil
}

// IsFlag reports whether a token is spelled like an option.
func IsFlag(token string) bool { return strings.HasPrefix(token, "-") }
