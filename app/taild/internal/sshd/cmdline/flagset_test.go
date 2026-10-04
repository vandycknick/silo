package cmdline

import (
	"strings"
	"testing"
	"time"
)

func TestFlagSetStrictness(t *testing.T) {
	var force, start bool
	var cpus uint64
	var owner, name string
	var timeout time.Duration
	labels := map[string]string{}
	parse := func(args ...string) (Args, error) {
		f := NewFlagSet()
		f.Bool("force", "Force.", &force)
		f.Bool("no-start", "Leave stopped.", &start)
		f.Alias("c", f.Value("cpus", "N", "CPUs.", Count(&cpus)))
		f.String("owner", "tag:NAME", "Owner.", &owner)
		f.Value("name", "NAME", "Name.", NonEmpty(&name))
		f.Value("timeout", "DURATION", "Deadline.", Duration(&timeout))
		f.Repeat("label", "K=V", "Label.", KeyValue(labels))
		return f.Parse(args)
	}
	args, e := parse("--force", "--cpus", "2", "--label", "a=1", "--label", "b=2", "--owner", "tag:x", "--timeout", "5s")
	if e != nil || !force || cpus != 2 || owner != "tag:x" || labels["a"] != "1" || labels["b"] != "2" || timeout != 5*time.Second {
		t.Fatal(e, force, cpus, owner, labels, timeout)
	}
	if e := args.None(); e != nil {
		t.Fatal(e)
	}
	if _, e := parse("--no-start=false", "-c=3", "--name", "-", "x", "y"); e != nil || start || cpus != 3 || name != "-" {
		t.Fatal("standard flag spellings rejected", e, start, cpus, name)
	}
	args, e = parse("vm", "--force", "--", "--force", "literal")
	if e != nil || len(args.Positional) != 1 || !args.Delimited || len(args.Literal) != 2 || args.Literal[0] != "--force" {
		t.Fatal(args, e)
	}
	if _, e := args.One("VM"); e == nil {
		t.Fatal("literal tail accepted by One")
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--force", "--force"}, "duplicate option --force"},
		{[]string{"--cpus", "2", "-c", "2"}, "duplicate option --c"},
		{[]string{"--cpus"}, "option --cpus requires a value"},
		{[]string{"--cpus", "lots"}, "invalid value for --cpus: expected a positive integer (1..255)"},
		{[]string{"--cpus", "0"}, "invalid value for --cpus: expected a positive integer (1..255)"},
		{[]string{"--timeout", "soon"}, "invalid value for --timeout"},
		{[]string{"--name", ""}, "invalid value for --name"},
		{[]string{"--label", "novalue"}, "invalid value for --label"},
		{[]string{"--unknown"}, "unknown option; see command help"},
		{[]string{"-h"}, "unknown option; see command help"},
	} {
		if _, e := parse(tc.args...); e == nil || e.Error() != tc.want {
			t.Fatalf("%q: %v, want %q", tc.args, e, tc.want)
		}
	}
	// Supplied values never appear in an error.
	if _, e := parse("--timeout", "tskey-secret"); e == nil || strings.Contains(e.Error(), "tskey") {
		t.Fatal(e)
	}
}

func TestArgsShapes(t *testing.T) {
	if v, e := (Args{Positional: []string{"vm"}}).One("VM"); e != nil || v != "vm" {
		t.Fatal(v, e)
	}
	if _, e := (Args{}).One("VM"); e == nil {
		t.Fatal("missing positional accepted")
	}
	if _, e := (Args{Positional: []string{"a", "b"}}).One("VM"); e == nil {
		t.Fatal("extra positional accepted")
	}
	if e := (Args{Positional: []string{"a"}}).None(); e == nil {
		t.Fatal("positional accepted by None")
	}
	if e := (Args{Delimited: true}).None(); e == nil {
		t.Fatal("delimiter accepted by None")
	}
	if !IsFlag("--x") || !IsFlag("-x") || IsFlag("x") {
		t.Fatal("IsFlag")
	}
}

func TestDeclarationDrivesArityAndHelp(t *testing.T) {
	var b bool
	var s string
	f := NewFlagSet()
	f.Bool("force", "Force.", &b)
	f.Alias("d", f.String("dir", "DIR", "Directory.", &s).Default("guest default"))
	if f.TakesValue("force") || !f.TakesValue("dir") || !f.TakesValue("d") || f.TakesValue("nope") {
		t.Fatal("arity")
	}
	options := f.Options()
	if len(options) != 2 || options[0].Names[0] != "force" || options[0].Fallback != "false" || options[1].Placeholder != "DIR" || options[1].Fallback != "guest default" || len(options[1].Names) != 2 {
		t.Fatalf("%+v", options)
	}
	if _, e := f.Parse([]string{"-d", "/tmp"}); e != nil || s != "/tmp" {
		t.Fatal(e, s)
	}
}

// Diagnostics name the option and the shape of the problem, never the value.
func TestUsageDiagnosticsRedacted(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--cpus"}, "requires a value"}, {[]string{"--cpus", "-1"}, "positive integer"},
		{[]string{"--cpus", "18446744073709551616"}, "positive integer"},
		{[]string{"--name", "one", "-n", "two"}, "duplicate option"},
		{[]string{"--name", ""}, "--name"}, {[]string{"--unknown=SECRET"}, "unknown option"},
		{[]string{"--label", "SECRET"}, "--label"}, {[]string{"--no-start=SECRET"}, "--no-start"},
		{[]string{"--cpus", "SECRET/token"}, "positive integer"},
		{[]string{"--cpus", "1SECRET"}, "positive integer"},
	} {
		var name string
		var cpus uint64
		var noStart bool
		f := NewFlagSet()
		f.Alias("n", f.Value("name", "NAME", "Name.", NonEmpty(&name)))
		f.Value("cpus", "N", "CPUs.", Count(&cpus))
		f.Bool("no-start", "Leave stopped.", &noStart)
		f.Repeat("label", "K=V", "Label.", KeyValue(map[string]string{}))
		_, err := f.Parse(tc.args)
		if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "SECRET") {
			t.Fatal(tc.args, err)
		}
	}
}
