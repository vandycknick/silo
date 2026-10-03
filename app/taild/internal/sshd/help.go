package sshd

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/units"
)

type flagHelp struct{ names, value, description, fallback string }
type commandMetadata struct {
	description, arguments, example string
	options                         []flagHelp
}

// Arity and help share one registry; an empty placeholder denotes a boolean.
var metadata = map[string]commandMetadata{
	"help":    {"Show command help.", "COMMAND [SUBCOMMAND]  Optional help topic.", "help template create", nil},
	"whoami":  {"Show your verified user and node.", "", "whoami --json", nil},
	"version": {"Show daemon, SDK and runtime versions.", "", "version", nil},
	"ls":      {"List your VMs.", "", "ls", nil},
	"show":    {"Inspect a VM.", "VM  Exact name or VM ID.", "show devbox", nil},
	"ops":     {"List operations or inspect one operation.", "show op_ULID  Optional operation selector.", "ops", nil},
	"create": {"Create and start a VM unless --no-start is supplied.", "IMAGE  Optional OCI reference (template, then configured default).", "create ghcr.io/example/dev:latest --name devbox --memory 4GiB", []flagHelp{
		{"n,name", "NAME", "Exact name; absent name is generated.", "generated"},
		{"image", "OCI", "Compatibility alias; cannot be combined with IMAGE.", "template/configured"},
		{"template", "NAME", "Apply a template; explicit options take precedence.", "none"},
		{"policy", "NAME", "Named network policy.", "template/configured"},
		{"cpus", "N", "Positive CPU count, 1..255, subject to grants.", "configured"},
		{"memory", "SIZE", "Binary memory size, e.g. 4GiB or 8gb.", "template/configured"},
		{"disk,disk-size", "SIZE", "Binary root disk size, e.g. 16GiB.", "template/configured"},
		{"provision-user", "NAME:UID:GID:HOME", "Provision the guest account.", "root"},
		{"userdata", "INLINE|-", "Shebang script; - reads stdin after authorization.", "template/none"},
		{"label", "K=V", "User label (repeatable).", "template/none"},
		{"owner", "tag:NAME", "Select a verified owner tag.", "your principal"},
		{"no-tailnet", "", "Disable VM enrollment.", "false"},
		{"no-start", "", "Leave the VM stopped.", "false"},
	}},
	"start":    {"Start a stopped VM.", "VM  Exact name or VM ID.", "start devbox", nil},
	"restart":  {"Restart a VM.", "VM  Exact name or VM ID.", "restart devbox", nil},
	"reauth":   {"Reauthenticate a stopped VM (requires start and stop grants).", "VM  Exact name or VM ID.", "reauth devbox", nil},
	"stop":     {"Stop a VM.", "VM  Exact name or VM ID.", "stop devbox --timeout 30s", []flagHelp{{"force", "", "Force shutdown.", "false"}, {"timeout", "DURATION", "Shutdown deadline.", "configured"}}},
	"rm":       {"Remove a VM after confirmation.", "VM  Exact name or VM ID.", "rm devbox --yes", []flagHelp{{"force", "", "Stop a running VM first.", "false"}, {"yes", "", "Bypass [y/N] confirmation.", "false"}}},
	"set":      {"Update a stopped VM.", "VM  Exact name or VM ID.\nKEY=VALUE  name, cpus, memory or disk. Sizes are binary.", "set devbox memory=8gb disk=16GiB", nil},
	"shell":    {"Open a guest shell (requires SSH PTY).", "VM  Exact name or VM ID.", "shell devbox -u root", []flagHelp{{"u", "USER", "Guest user.", "VM default"}}},
	"exec":     {"Run a guest command; arguments after -- are literal.", "VM  Exact name or VM ID.\nCMD...  Guest program and arguments after --.", "exec devbox -- uname -a", []flagHelp{{"u", "USER", "Guest user.", "VM default"}, {"w", "DIR", "Working directory.", "guest default"}, {"e", "K=V", "Environment (repeatable).", "none"}, {"t", "", "Guest PTY.", "false"}}},
	"logs":     {"Read bounded VM logs.", "VM  Exact name or VM ID.", "logs devbox --stream serial", []flagHelp{{"follow", "", "Follow output.", "false"}, {"stream", "STREAM", "monitor, serial, exec, network or network-audit.", "monitor"}, {"output", "OUTPUT", "stdout or stderr.", "stdout"}}},
	"template": {"Manage YAML templates: ls, show, create, edit, rm, validate.", "SUBCOMMAND  create/edit/validate read one YAML document from stdin.", "help template create", []flagHelp{{"owner", "tag:NAME", "Verified owner namespace.", "your principal"}}},
	"policy":   {"Manage HCL policies: ls, show, create, edit, rm, validate.", "SUBCOMMAND  create/edit/validate read HCL from stdin.", "help policy validate", []flagHelp{{"owner", "tag:NAME", "Verified owner namespace.", "your principal"}}},
}

func canonicalCommand(name string) string {
	if c, ok := aliases[name]; ok {
		return c
	}
	return name
}

// This capability drives both dispatch and help, rather than a second list in
// each streaming handler. Help itself can still be requested through `help --json`.
func acceptsJSON(name string) bool {
	switch canonicalCommand(name) {
	case "shell", "exec", "logs":
		return false
	default:
		return true
	}
}
func optionTakesValue(command, option string) bool {
	for _, f := range metadata[canonicalCommand(command)].options {
		for _, name := range strings.Split(f.names, ",") {
			if name == option {
				return f.value != ""
			}
		}
	}
	return false
}

func generalHelp() string {
	var b strings.Builder
	b.WriteString("silo · VMs on your tailnet\n\nUsage:\n  COMMAND [ARGUMENTS] [OPTIONS]\n\nCommands:\n")
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	var names []string
	for name := range commands {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(w, "  %s\t%s\n", name, metadata[name].description)
	}
	_ = w.Flush()
	b.WriteString("\nOptions:\n  -h, --help  Show help.\n  --json      Structured output for supported queries/mutations.\n\nExamples:\n  help create\n  create --name devbox --memory 4GiB\n")
	return b.String()
}

func detailedHelp(path []string, configured ...config.Config) (string, bool) {
	if len(path) == 0 {
		return generalHelp(), true
	}
	name := canonicalCommand(path[0])
	c, ok := commands[name]
	if !ok {
		return "", false
	}
	m := metadata[name]
	grammar := c.usage
	if len(path) == 2 && name == "ops" {
		if path[1] != "show" {
			return "", false
		}
		grammar = "ops show OPERATION_ID [OPTIONS]"
		m.description = "Inspect an operation owned by your principal."
		m.arguments = "OPERATION_ID  The op_ULID returned by a command."
		m.example = "ops show op_01ARZ3NDEKTSV4RRFFQ69G5FAV --json"
	} else if len(path) > 1 {
		if len(path) != 2 || name != "template" && name != "policy" {
			return "", false
		}
		verb := path[1]
		switch verb {
		case "ls", "validate":
			grammar = name + " " + verb + " [OPTIONS]"
			m.arguments = ""
		case "show", "create", "edit", "rm":
			grammar = name + " " + verb + " NAME [OPTIONS]"
			m.arguments = "NAME  Document name in your namespace."
		default:
			return "", false
		}
		m.description = "Manage a " + name + " document."
		if verb == "create" || verb == "edit" || verb == "validate" {
			m.description += " Reads one document from stdin."
		}
		m.example = name + " " + verb
		if verb != "ls" && verb != "validate" {
			m.example += " dev"
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\nUsage:\n  %s\n", m.description, grammar)
	var aliasNames []string
	for alias, target := range aliases {
		if target == name {
			aliasNames = append(aliasNames, alias)
		}
	}
	sort.Strings(aliasNames)
	if len(aliasNames) > 0 {
		fmt.Fprintf(&b, "\nAliases:\n  %s\n", strings.Join(aliasNames, ", "))
	}
	if m.arguments != "" {
		fmt.Fprintf(&b, "\nArguments:\n  %s\n", strings.ReplaceAll(m.arguments, "\n", "\n  "))
	}
	b.WriteString("\nOptions:\n")
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	options := append([]flagHelp(nil), m.options...)
	options = append(options, flagHelp{"h,help", "", "Show help.", ""})
	if acceptsJSON(name) {
		options = append(options, flagHelp{"json", "", "Structured output; does not confirm removal.", "false"})
	}
	for _, f := range options {
		if name == "create" && len(configured) > 0 {
			f.fallback = configuredDefault(f, configured[0])
		}
		var spellings []string
		for _, n := range strings.Split(f.names, ",") {
			prefix := "--"
			if len(n) == 1 {
				prefix = "-"
			}
			spellings = append(spellings, prefix+n)
		}
		label := strings.Join(spellings, ", ")
		if f.value != "" {
			label += " " + f.value
		}
		description := f.description
		if f.fallback != "" {
			description += " (default: " + f.fallback + ")"
		}
		fmt.Fprintf(w, "  %s\t%s\n", label, description)
	}
	_ = w.Flush()
	fmt.Fprintf(&b, "\nExamples:\n  %s\n", m.example)
	return b.String(), true
}

func configuredDefault(spec flagHelp, c config.Config) string {
	value := ""
	switch spec.names {
	case "cpus":
		value = "unavailable"
		if c.VM.Defaults.CPUs > 0 && c.VM.Defaults.CPUs <= 255 {
			value = strconv.FormatUint(c.VM.Defaults.CPUs, 10)
		}
	case "memory":
		value = safeConfiguredSize(c.VM.Defaults.Memory)
	case "disk,disk-size":
		value = safeConfiguredSize(c.VM.Defaults.Disk)
	case "image":
		value = service.ImageDefaultForHelp(c)
	default:
		return spec.fallback
	}
	return value + "; template takes precedence, explicit option overrides both"
}

func safeConfiguredSize(value string) string {
	if n, err := units.Bytes(value); err != nil || n == 0 || len(value) > 64 {
		return "unavailable"
	}
	return strings.TrimSpace(value)
}
