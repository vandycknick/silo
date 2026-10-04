package commands

import (
	"strings"
	"testing"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/sshd/cmdline"
)

func TestRegistryIsTheWholeApplication(t *testing.T) {
	want := []string{"whoami", "version", "help", "ls", "show", "ops", "create", "start", "restart", "reauth", "stop", "rm", "set", "shell", "exec", "logs", "template", "policy"}
	if len(all) != len(want) {
		t.Fatal(len(all), len(want))
	}
	seen := map[string]bool{}
	for i, c := range all {
		if c.Name != want[i] || seen[c.Name] || c.Summary == "" || c.Usage == "" || c.Example == "" || c.New == nil {
			t.Fatalf("command %d: %+v", i, c)
		}
		seen[c.Name] = true
		for _, alias := range c.Aliases {
			if seen[alias] {
				t.Fatal("alias collides", alias)
			}
			seen[alias] = true
			if resolved, ok := lookup(alias); !ok || resolved.Name != c.Name {
				t.Fatal("alias does not resolve", alias)
			}
		}
	}
	for _, alias := range []string{"list", "new", "status", "ssh"} {
		if !seen[alias] {
			t.Fatal("missing alias", alias)
		}
	}
	if _, ok := lookup("bogus"); ok {
		t.Fatal("unknown command resolved")
	}
}

// One declaration per option drives parsing, the session-flag scanner and
// help, so what help documents is exactly what the parser accepts.
func TestDeclarationsDriveHelpAndArity(t *testing.T) {
	cfg := config.Defaults()
	for _, c := range all {
		flags := flagsOf(c)
		text, ok := detailedHelp([]string{c.Name}, &cfg)
		if !ok || !strings.Contains(text, "Usage:\n  "+c.Usage) || !strings.Contains(text, "Examples:\n  "+c.Example) {
			t.Fatal(c.Name, ok, text)
		}
		if strings.Contains(text, "--json") == c.Streaming {
			t.Fatal("JSON help mismatch", c.Name, text)
		}
		for _, o := range flags.Options() {
			if o.Help == "" || o.Fallback == "" {
				t.Fatalf("%s: option %v lacks help or default", c.Name, o.Names)
			}
			for _, name := range o.Names {
				spelling := "--" + name
				if len(name) == 1 {
					spelling = "-" + name
				}
				if !strings.Contains(text, spelling) {
					t.Fatal("option missing from help", c.Name, spelling)
				}
			}
			// Every declared option is wired to a parser the handler owns.
			args := []string{"--" + o.Names[0]}
			if o.Placeholder != "" {
				args = append(args, "x")
			}
			f := cmdline.NewFlagSet()
			c.New().Flags(f)
			if _, e := f.Parse(args); e != nil && !strings.HasPrefix(e.Error(), "invalid value for") {
				t.Fatal(c.Name, args, e)
			}
		}
		if c.Topics != nil {
			if _, ok := c.Topics("bogus"); ok {
				t.Fatal("unknown topic accepted", c.Name)
			}
		}
	}
	for _, path := range [][]string{{"ops", "show"}, {"template", "create"}, {"policy", "validate"}, {"new"}, {"list"}} {
		if text, ok := detailedHelp(path, nil); !ok || !strings.Contains(text, "Options:") {
			t.Fatal(path, ok, text)
		}
	}
	for _, path := range [][]string{{"bogus"}, {"ops", "list"}, {"template", "bogus"}, {"ls", "extra"}, {"template", "create", "extra"}} {
		if _, ok := detailedHelp(path, nil); ok {
			t.Fatal("unknown topic rendered", path)
		}
	}
	for _, name := range []string{"create", "exec", "help", "ls", "logs", "ops", "policy", "reauth", "restart", "rm", "set", "shell", "show", "start", "stop", "template", "version", "whoami"} {
		if !strings.Contains(generalHelp(), "\n  "+name+" ") {
			t.Fatal("general help misses", name)
		}
	}
}
