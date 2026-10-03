package sshd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/state"
	silo "github.com/vandycknick/silo/sdk/go"
)

func TestCLIHelpPureAndLiteralValues(t *testing.T) {
	audit, err := state.OpenAudit(t.TempDir(), 1<<20, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	s := &service.Service{Audit: audit, Config: config.Defaults()}
	p := identity.Peer{Principals: []identity.Principal{"user:7"}, NodeID: "help", Login: "verified@example.com", NodeName: "node.tail.test.", ObservedAt: time.Now()}
	caller := service.Caller{Peer: p}
	inputFile, err := os.CreateTemp(t.TempDir(), "input")
	if err != nil {
		t.Fatal(err)
	}
	defer inputFile.Close()
	if _, err = inputFile.WriteString("secret input\n"); err != nil {
		t.Fatal(err)
	}
	if _, err = inputFile.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	input := newInput(t.Context(), inputFile)
	// No runtime or jobs exist; the real input file must remain unread.
	var topics []string
	for name := range commands {
		topics = append(topics, name+" --help", name+" -h", "help "+name)
	}
	for alias := range aliases {
		topics = append(topics, alias+" --help", "help "+alias)
	}
	for _, kind := range []string{"template", "policy"} {
		for _, verb := range []string{"ls", "show", "create", "edit", "rm", "validate"} {
			topics = append(topics, kind+" "+verb+" --help", "help "+kind+" "+verb)
		}
	}
	topics = append(topics, "--help", "-h", "create --userdata - --help", "help ops show", "ops show --help", "ops show -h")
	for _, line := range topics {
		var out, human bytes.Buffer
		code := DispatchSession(t.Context(), s, caller, line, service.IO{Stdin: input.Reader(t.Context()), Input: input.Reader, Stdout: &out, Stderr: &human})
		if code != 0 || !strings.Contains(human.String(), "Usage:") || !strings.Contains(human.String(), "Options:") || !strings.Contains(human.String(), "Examples:") {
			t.Fatalf("%s: %d %s", line, code, human.String())
		}
	}
	if position, err := inputFile.Seek(0, io.SeekCurrent); err != nil || position != 0 {
		t.Fatal("help read stdin", position, err)
	}
	for _, line := range []string{"create --userdata '--help'", "create --userdata '--json'", "create --label 'K=--help'", "exec vm -- program --help", "exec vm -u --help -- program"} {
		var out, human bytes.Buffer
		code := DispatchSession(t.Context(), s, caller, line, service.IO{Stdout: &out, Stderr: &human})
		if code != 4 || strings.Contains(human.String(), "Usage:") || out.Len() != 0 {
			t.Fatalf("literal %s: %d %s %s", line, code, out.String(), human.String())
		}
	}
	var out, human bytes.Buffer
	if code := Dispatch(s, p, "whoami", &out, &human); code != 0 || human.String() != "User: verified@example.com\nNode: node.tail.test\n" {
		t.Fatal(code, human.String())
	}
	human.Reset()
	p.Principals = []identity.Principal{"tag:ci"}
	Dispatch(s, p, "whoami", &out, &human)
	if human.String() != "User: tagged device\nNode: node.tail.test\n" {
		t.Fatal(human.String())
	}
	human.Reset()
	p.Principals = []identity.Principal{"user:7"}
	p.Login = ""
	Dispatch(s, p, "whoami", &out, &human)
	if !strings.HasPrefix(human.String(), "User: unknown\n") {
		t.Fatal(human.String())
	}
}

func TestCLIUsageDiagnosticsRedacted(t *testing.T) {
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
		f := newFlagSet()
		f.Alias("n", f.Flag("name", nonEmpty(&name)))
		f.Flag("cpus", count(&cpus))
		f.Bool("no-start", &noStart)
		f.Repeat("label", keyValue(map[string]string{}))
		err := f.Parse(tc.args)
		if err == nil || service.Categorize(err).Exit != 2 || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "SECRET") {
			t.Fatal(tc.args, err)
		}
	}
}

func TestCLIFlagMetadataMatchesActualParsers(t *testing.T) {
	audit, err := state.OpenAudit(t.TempDir(), 1<<20, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	s := &service.Service{Audit: audit, Config: config.Defaults()}
	p := identity.Peer{Principals: []identity.Principal{"user:7"}, NodeID: "metadata", ObservedAt: time.Now()}
	for name, cmd := range commands {
		m, ok := metadata[name]
		if !ok || m.description == "" || m.example == "" {
			t.Fatal("missing command metadata", name)
		}
		help, ok := commandHelp(name)
		if !ok {
			t.Fatal("missing help", name)
		}
		if strings.Contains(help, "--json") != acceptsJSON(name) {
			t.Fatal("JSON help mismatch", name, help)
		}
		var prefixes [][]string
		switch name {
		case "create":
			prefixes = [][]string{{}}
		case "stop", "rm", "shell", "logs":
			prefixes = [][]string{{"vm"}}
		case "exec":
			prefixes = [][]string{{"vm"}}
		case "template", "policy":
			for _, verb := range []string{"ls", "show", "create", "edit", "rm", "validate"} {
				prefix := []string{verb}
				if verb != "ls" && verb != "validate" {
					prefix = append(prefix, "document")
				}
				prefixes = append(prefixes, prefix)
				nested, ok := commandHelp(name + " " + verb)
				if !ok || !strings.Contains(nested, "--json") {
					t.Fatal("missing nested options", name, verb)
				}
			}
		default:
			if len(m.options) != 0 {
				t.Fatal("new flag-bearing command needs a positional grammar fixture", name)
			}
		}
		for _, spec := range m.options {
			if spec.description == "" || spec.fallback == "" {
				t.Fatal("missing description/default", name, spec)
			}
			for _, alias := range strings.Split(spec.names, ",") {
				if optionTakesValue(name, alias) != (spec.value != "") {
					t.Fatal("scanner arity", name, alias)
				}
				spelling := "--" + alias
				if len(alias) == 1 {
					spelling = "-" + alias
				}
				if !strings.Contains(help, spelling) {
					t.Fatal("missing option alias in help", name, alias)
				}
			}
		}
		for _, prefix := range prefixes {
			args := append(append([]string(nil), prefix...), "--unknown")
			if name == "exec" {
				args = append(args, "--", "program")
			}
			// Run the real handler's registrations, then stop at a syntax error.
			// Parse checks both missing/extra specs, bool/value arity and alias identity.
			_, err := cmd.run(&invocation{}, args)
			if err == nil || service.Categorize(err).Message != "unknown option; see command help" {
				t.Fatal("registration consistency", name, prefix, err)
			}
			for _, spec := range m.options {
				for _, alias := range strings.Split(spec.names, ",") {
					args = append([]string(nil), prefix...)
					flag := "--" + alias
					if len(alias) == 1 {
						flag = "-" + alias
					}
					if spec.value == "" {
						args = append(args, flag)
					} else {
						args = append(args, flag, "--help")
					}
					args = append(args, "--unknown")
					if name == "exec" {
						args = append(args, "--", "program", "--json", "--help")
					}
					var out, human bytes.Buffer
					line := strings.Join(append([]string{name}, args...), " ")
					if code := DispatchSession(t.Context(), s, service.Caller{Peer: p}, line, service.IO{Stdout: &out, Stderr: &human}); code != 2 || strings.Contains(human.String(), "Usage:") || out.Len() != 0 {
						t.Fatal("actual parser arity/help literal", line, code, out.String(), human.String())
					}
				}
			}
		}
	}
	for _, line := range []string{"shell vm --json", "exec vm --json -- program", "logs vm --json"} {
		var out, human bytes.Buffer
		if code := Dispatch(s, p, line, &out, &human); code != 2 || !strings.Contains(human.String(), "--json is not supported") {
			t.Fatal(line, code, human.String())
		}
	}
	wrongDefault := true
	f := newFlagSet("rm")
	f.Bool("force", &wrongDefault)
	if err := f.checkMetadata(); err == nil {
		t.Fatal("boolean default drift was not detected")
	}
}

func TestCLIHelpConfiguredDefaultsArePureAndSafe(t *testing.T) {
	audit, err := state.OpenAudit(t.TempDir(), 1<<20, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	c := config.Defaults()
	c.VM.Defaults = config.Resources{CPUs: 3, Memory: "4GB", Disk: "7GiB"}
	c.VM.DefaultImage = "ghcr.io/example/dev:latest"
	c.VM.AllowedRegistries = []string{"ghcr.io/example"}
	s := &service.Service{Audit: audit, Config: c}
	p := identity.Peer{Principals: []identity.Principal{"user:7"}, NodeID: "defaults", ObservedAt: time.Now()}
	for _, line := range []string{"create --help", "help new", "help create --json"} {
		var out, human bytes.Buffer
		if code := Dispatch(s, p, line, &out, &human); code != 0 {
			t.Fatal(code, human.String())
		}
		text := human.String()
		if strings.HasSuffix(line, "--json") {
			var envelope struct {
				Data struct {
					Help string `json:"help"`
				} `json:"data"`
			}
			if err := json.Unmarshal(out.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			text = envelope.Data.Help
		}
		for _, expected := range []string{"default: 3;", "default: 4GB;", "default: 7GiB;", "default: ghcr.io/example/dev:latest;", "template takes precedence, explicit option overrides both"} {
			if !strings.Contains(text, expected) {
				t.Fatal("configured default missing", expected, text)
			}
		}
	}
	if s.Config.VM.Defaults != c.VM.Defaults || s.Config.VM.DefaultImage != c.VM.DefaultImage {
		t.Fatal("help mutated config")
	}
	for _, image := range []string{"/SECRET/token", "https://ghcr.io/example?token=SECRET", "ghcr.io:SECRET@example.test/image", "ghcr.io:SECRET/example/dev", "elsewhere.test/SECRET/image"} {
		s.Config.VM.DefaultImage = image
		s.Config.VM.Defaults.Memory = "4SECRET"
		s.Config.VM.Defaults.Disk = "SECRET/token"
		for _, line := range []string{"create --help", "help create --json"} {
			var out, human bytes.Buffer
			if code := Dispatch(s, p, line, &out, &human); code != 0 || strings.Contains(out.String()+human.String(), "SECRET") {
				t.Fatal("unsafe configured defaults", code, out.String(), human.String())
			}
		}
	}
	for _, line := range []string{"help ops show", "ops show --help", "ops show -h --json"} {
		var out, human bytes.Buffer
		if code := Dispatch(s, p, line, &out, &human); code != 0 || !strings.Contains(out.String()+human.String(), "ops show OPERATION_ID") {
			t.Fatal(line, code, out.String(), human.String())
		}
	}
}

func TestCLIHelpWithoutNativeBridge(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	t.Setenv("SILO_GO_FFI_PATH", t.TempDir()+"/missing-native-library")
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCLIHelp(PureAndLiteralValues|ConfiguredDefaultsArePureAndSafe)$")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatal("pure help required native planning/runtime", err, string(output))
	}
}

func TestCLINativeGeneratedResourcesAndOpenSSHExit(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	s, caller, registry := nativeService(t, ctx, "cli-ux", "user:7")
	address := terminalSSHServer(t, s, caller)
	for _, tty := range []bool{false, true} {
		for _, tc := range []struct {
			line string
			code int
			text string
		}{
			{"create --help", 0, "Usage:"}, {"help template create", 0, "Usage:"},
			{"help ops show", 0, "ops show OPERATION_ID"}, {"ops show --help", 0, "ops show OPERATION_ID"},
			{"create --memory bad", 2, "invalid value for --memory"}, {"create --name", 2, "requires a value"},
			{"create --unknown=SECRET", 2, "unknown option"},
			{"create --cpus SECRET/token", 2, "positive integer"},
			{"create --cpus 1SECRET --json", 2, "positive integer"},
			{"create --memory SECRET/token --json", 2, "--memory"},
			{"create --memory 8SECRET", 2, "4GiB or 8gb"},
			{"create --disk-size SECRET/token --json", 2, "--disk"},
			{"create --disk-size 2SECRET", 2, "4GiB or 8gb"},
		} {
			out, diagnostic, code := sshPipeCommand(t, address, tc.line, nil, tty)
			if code != tc.code || !bytes.Contains(diagnostic, []byte(tc.text)) || bytes.Contains(diagnostic, []byte("SECRET")) || bytes.Contains(out, []byte("SECRET")) {
				t.Fatalf("PTY=%t %s: %d %q", tty, tc.line, code, diagnostic)
			}
			if tty {
				assertTerminalNewlines(t, string(diagnostic))
			}
		}
	}
	if len(s.Jobs.List(caller.Peer)) != 0 || registry.Requests.Load() != 0 {
		t.Fatal("help/invalid syntax started work")
	}
	s.VMNodesEnabled = true
	s.Config.Enrollment.Mode = "interactive"
	var out, diagnostic bytes.Buffer
	if code := DispatchSession(ctx, s, caller, "create --memory 8gb --disk-size ' 2 GB ' --no-start --json", service.IO{Stdout: &out, Stderr: &diagnostic}); code != 0 {
		t.Fatal(code, diagnostic.String())
	}
	var envelope struct {
		Data jobs.Operation `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	name := envelope.Data.VM
	if !config.ValidName(name) || name == "" || !strings.Contains(diagnostic.String(), "creating "+name) {
		t.Fatal(name, diagnostic.String())
	}
	view, err := s.Show(ctx, caller.Peer, name)
	if err != nil {
		t.Fatal(err)
	}
	if view.Memory != 8<<30 || view.Disk != 2<<30 {
		t.Fatal(view.Memory, view.Disk)
	}
	machine, err := s.Runtime.SDK.Machine(ctx, view.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer machine.Close()
	data, err := machine.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if data.Name != name || data.Labels[runtime.NameLabel] != name {
		t.Fatal(data)
	}
	if data.Network.Tailscale == nil || data.Network.Tailscale.Hostname != name {
		t.Fatal("generated hostname", data.Network)
	}
	s.VMNodesEnabled = false
	if code := DispatchSession(ctx, s, caller, fmt.Sprintf("create %s --no-start -n exact", registry.Reference), service.IO{Stdout: io.Discard, Stderr: &diagnostic}); code != 0 {
		t.Fatal(code, diagnostic.String())
	}
	defaults, err := s.Show(ctx, caller.Peer, "exact")
	if err != nil || defaults.CPUs != uint8(s.Config.VM.Defaults.CPUs) || defaults.Memory != 256<<20 || defaults.Disk != 1<<30 || defaults.DefaultUser != "root" {
		t.Fatal("actual configured/default guest values", defaults, err)
	}
	for _, setting := range []string{"cpus=SECRET/token", "cpus=1SECRET", "memory=SECRET/token", "memory=8SECRET", "disk=SECRET/token", "disk=2SECRET"} {
		for _, structured := range []bool{false, true} {
			line := "set exact " + setting
			if structured {
				line += " --json"
			}
			out.Reset()
			diagnostic.Reset()
			if code := DispatchSession(ctx, s, caller, line, service.IO{Stdout: &out, Stderr: &diagnostic}); code != 2 || strings.Contains(out.String()+diagnostic.String(), "SECRET") {
				t.Fatal("set diagnostic", code, out.String(), diagnostic.String())
			}
			field, _, _ := strings.Cut(setting, "=")
			if !strings.Contains(diagnostic.String(), field) {
				t.Fatal("missing setting context", diagnostic.String())
			}
		}
	}
	if code := DispatchSession(ctx, s, caller, "create --name exact --no-start", service.IO{Stdout: io.Discard, Stderr: &diagnostic}); code != 5 {
		t.Fatal("exact collision", code, diagnostic.String())
	}
	if code := DispatchSession(ctx, s, caller, "set exact memory=512mb disk=3gb", service.IO{Stdout: io.Discard, Stderr: &diagnostic}); code != 0 {
		t.Fatal(code, diagnostic.String())
	}
	view, err = s.Show(ctx, caller.Peer, "exact")
	if err != nil || view.Memory != 512<<20 || view.Disk != 3<<30 {
		t.Fatal(view, err)
	}
	// Decimal constructors and quota/config parsing retain their separate contracts.
	if silo.Gigabytes(8).Bytes() != 8000000000 {
		t.Fatal("decimal constructor changed")
	}
	raw := "version: '1'\nresources:\n  memory: '512mb'\ndisk_size: '2 gb'\n"
	if code := DispatchSession(ctx, s, caller, "template create binary", service.IO{Stdin: strings.NewReader(raw), Stdout: io.Discard, Stderr: &diagnostic}); code != 0 {
		t.Fatal(code, diagnostic.String())
	}
	if code := DispatchSession(ctx, s, caller, "create --template binary --name templated --no-start", service.IO{Stdout: io.Discard, Stderr: &diagnostic}); code != 0 {
		t.Fatal(code, diagnostic.String())
	}
	view, err = s.Show(ctx, caller.Peer, "templated")
	if err != nil || view.Memory != 512<<20 || view.Disk != 2<<30 {
		t.Fatal(view, err)
	}
}
