package commands

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/sshd/cmdline"
)

func TestDeclarationDrivenSessionGrammar(t *testing.T) {
	for _, cmd := range all {
		for _, verb := range append([]string{cmd.Name}, cmd.Aliases...) {
			for _, option := range flagsOf(cmd).Options() {
				for _, name := range option.Names {
					for _, value := range []string{"--help", "--json", "--yes", "--"} {
						t.Run(verb+"/"+name+"/"+value, func(t *testing.T) {
							spelling := "--" + name
							if len(name) == 1 {
								spelling = "-" + name
							}
							line := []string{verb, spelling}
							if option.Placeholder != "" {
								line = append(line, value)
							}
							line = append(line, "--unknown=SECRET")
							c := &Context{Context: t.Context()}
							kept, help, err := c.sessionFlags(line, flagsOf(cmd))
							if err != nil || help || c.JSON || !reflect.DeepEqual(kept, line) {
								t.Fatalf("scanner: %v %t %t %v", kept, help, c.JSON, err)
							}
							_, err = Execute(&Context{Context: t.Context()}, line)
							var usage *authz.Error
							if !errors.As(err, &usage) || usage.Exit != 2 || strings.Contains(err.Error(), "SECRET") {
								t.Fatalf("Execute must reject before domain: %v", err)
							}
							if option.Placeholder == "" {
								for _, suffix := range []string{"", "=true", "=false"} {
									parsed, parseErr := flagsOf(cmd).Parse([]string{spelling + suffix})
									if parseErr != nil || len(parsed.Positional) != 0 || parsed.Delimited {
										t.Fatal("Boolean declaration did not parse", spelling, suffix, parsed, parseErr)
									}
									result, err := Execute(&Context{Context: t.Context()}, []string{verb, spelling + suffix, "--help"})
									if err != nil || !strings.Contains(result.Human, "Usage:") {
										t.Fatal(suffix, err, result)
									}
								}
							}
						})
					}
				}
			}
		}
	}
}

func TestLiteralTailAndDelimiterValue(t *testing.T) {
	line := []string{"exec", "vm", "--", "program", "--", "--json", "--help", "--yes", "SECRET"}
	c := &Context{Context: t.Context()}
	kept, help, err := c.sessionFlags(line, flagsOf(exec))
	if err != nil || help || c.JSON || !reflect.DeepEqual(kept, line) {
		t.Fatal(kept, help, err)
	}
	args, err := flagsOf(exec).Parse(kept[1:])
	if err != nil || !args.Delimited || !reflect.DeepEqual(args.Literal, line[3:]) || !reflect.DeepEqual(args.Positional, []string{"vm"}) {
		t.Fatal(args, err)
	}
	h := create.New().(*createHandler)
	f := cmdline.NewFlagSet()
	h.Flags(f)
	line = []string{"create", "--userdata", "--", "image"}
	kept, help, err = c.sessionFlags(line, f)
	if err != nil || help || !reflect.DeepEqual(kept, line) {
		t.Fatal(kept, help, err)
	}
	args, err = f.Parse(kept[1:])
	if err != nil || args.Delimited || h.q.Userdata != "--" || !reflect.DeepEqual(args.Positional, []string{"image"}) {
		t.Fatal(args, h.q.Userdata, err)
	}
}

func TestYesHasOneOccurrenceBudget(t *testing.T) {
	for _, first := range []string{"--yes", "--yes=true", "--yes=false", "-yes", "-yes=false"} {
		for _, second := range []string{"--yes", "--yes=true", "--yes=false", "-yes=false"} {
			for _, line := range [][]string{{"rm", "dev", first, second}, {first, "rm", "dev", second}, {first, second, "rm", "dev"}} {
				_, err := Execute(&Context{Context: t.Context()}, line)
				var usage *authz.Error
				if !errors.As(err, &usage) || usage.Exit != 2 || !strings.Contains(usage.Message, "duplicate option") {
					t.Fatal(line, err)
				}
			}
		}
	}
	for _, value := range []string{"false", "0", "f", "F", "FALSE", "False", "true", "1", "t", "T", "TRUE", "True"} {
		h := &rmHandler{}
		f := cmdline.NewFlagSet()
		h.Flags(f)
		if _, err := f.Parse([]string{"--yes=" + value}); err != nil {
			t.Fatal(value, err)
		}
		want := value == "1" || strings.EqualFold(value, "true") || strings.EqualFold(value, "t")
		if h.yes != want {
			t.Fatal(value, h.yes)
		}
	}
}

func TestSafePositionalDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		line            []string
		command, reason string
	}{
		{[]string{"rm"}, "rm", "missing VM argument"},
		{[]string{"status"}, "show", "missing VM argument"},
		{[]string{"start"}, "start", "missing VM argument"},
		{[]string{"restart"}, "restart", "missing VM argument"},
		{[]string{"reauth"}, "reauth", "missing VM argument"},
		{[]string{"stop"}, "stop", "missing VM argument"},
		{[]string{"ssh"}, "shell", "missing VM argument"},
		{[]string{"logs"}, "logs", "missing VM argument"},
		{[]string{"exec", "vm"}, "exec", "missing CMD (after --) argument"},
		{[]string{"exec", "--", "SECRET"}, "exec", "missing VM argument"},
		{[]string{"template", "create"}, "template", "missing NAME argument"},
		{[]string{"policy", "show"}, "policy", "missing NAME argument"},
		{[]string{"ops", "show"}, "ops", "missing OPERATION_ID argument"},
		{[]string{"set"}, "set", "missing VM argument"},
		{[]string{"set", "vm"}, "set", "missing KEY=VALUE argument"},
		{[]string{"whoami", "SECRET"}, "whoami", "unexpected positional argument"},
		{[]string{"version", "SECRET"}, "version", "unexpected positional argument"},
		{[]string{"ls", "SECRET"}, "ls", "unexpected positional argument"},
		{[]string{"rm", "vm", "SECRET"}, "rm", "unexpected VM argument"},
		{[]string{"rm", "vm", "--", "SECRET"}, "rm", "unexpected literal arguments after --"},
		{[]string{"create", "image", "SECRET"}, "create", "unexpected IMAGE argument"},
		{[]string{"help", "rm", "vm", "SECRET"}, "help", "unexpected help topic argument"},
	} {
		_, err := Execute(&Context{Context: t.Context()}, tc.line)
		var usage *authz.Error
		want := tc.command + ": " + tc.reason + ". See '" + tc.command + " --help'."
		if !errors.As(err, &usage) || usage.Exit != 2 || usage.Message != want {
			t.Fatal(tc.line, err, want)
		}
	}
}

func TestLogDeclarationLeavesDomainDefaults(t *testing.T) {
	h := logs.New().(*logsHandler)
	f := cmdline.NewFlagSet()
	h.Flags(f)
	if _, err := f.Parse(nil); err != nil {
		t.Fatal(err)
	}
	// Empty output means no filter, including any SDK output channel. Help's
	// "all" is descriptive text, not an unsupported value sent to the SDK.
	if h.q != (service.LogsRequest{}) {
		t.Fatal("help defaults applied as flag values", h.q)
	}
}
