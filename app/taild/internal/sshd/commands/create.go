package commands

import (
	"errors"
	"strconv"
	"strings"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/sshd/cmdline"
	silo "github.com/vandycknick/silo/sdk/go"
)

var create = Command{
	Name:      "create",
	Summary:   "Create and start a VM unless --no-start is supplied.",
	Usage:     "create [IMAGE] [-n/--name NAME] [OPTIONS]",
	Arguments: "IMAGE  Optional OCI reference (template, then configured default).",
	Example:   "create ghcr.io/example/dev:latest --name devbox --memory 4GiB",
	Aliases:   []string{"new"},
	New:       func() Handler { return &createHandler{q: service.CreateRequest{Labels: map[string]string{}}} },
}

type createHandler struct {
	q        service.CreateRequest
	image    *cmdline.Option
	userdata *cmdline.Option
}

func (h *createHandler) Flags(f *cmdline.FlagSet) {
	f.Alias("n", f.Value("name", "NAME", "Exact name; absent name is generated.", func(v string) error {
		if !config.ValidName(v) {
			return errors.New("invalid name")
		}
		h.q.Name = v
		return nil
	}).Default("generated"))
	h.image = f.Value("image", "OCI", "Compatibility alias; cannot be combined with IMAGE.", cmdline.NonEmpty(&h.q.Image)).Default("template/configured")
	f.Value("template", "NAME", "Apply a template; explicit options take precedence.", cmdline.NonEmpty(&h.q.Template)).Default("none")
	f.Value("policy", "NAME", "Named network policy.", cmdline.NonEmpty(&h.q.PolicyRef)).Default("template/configured")
	f.Value("cpus", "N", "Positive CPU count, 1..255, subject to grants.", cmdline.Count(&h.q.CPUs)).Default("configured")
	f.Value("memory", "SIZE", "Binary memory size, e.g. 4GiB or 8gb.", cmdline.NonEmpty(&h.q.MemoryText)).Default("template/configured")
	f.Alias("disk-size", f.Value("disk", "SIZE", "Binary root disk size, e.g. 16GiB.", cmdline.NonEmpty(&h.q.DiskText)).Default("template/configured"))
	f.Value("provision-user", "NAME:UID:GID:HOME", "Provision the guest account.", func(v string) error {
		u, e := silo.ParseGuestUser(v)
		h.q.GuestUser = &u
		return e
	}).Default("root")
	h.userdata = f.String("userdata", "INLINE|-", "Shebang script; - reads stdin after authorization.", &h.q.Userdata).Default("template/none")
	f.Repeat("label", "K=V", "User label (repeatable).", func(v string) error {
		k, value, ok := strings.Cut(v, "=")
		if _, dup := h.q.Labels[k]; !ok || dup {
			return errors.New("invalid or repeated label")
		}
		h.q.Labels[k] = value
		return nil
	}).Default("template/none")
	f.Value("owner", "tag:NAME", "Select a verified owner tag.", principal(&h.q.Owner)).Default("your principal")
	f.Bool("tailscale", "Add a VM tailnet node; interactive approval continues after boot.", &h.q.Tailscale)
	f.Repeat("tag", "tag:NAME", "Request a Tailscale tag (repeatable); Tailscale authorizes assignment.", func(v string) error {
		p, err := identity.ParsePrincipal(strings.ToLower(v))
		if err != nil || !p.IsTag() {
			return errors.New("expected tag:NAME")
		}
		h.q.Tags = append(h.q.Tags, string(p))
		return nil
	}).Default("none")
	f.Bool("no-start", "Leave the VM stopped.", &h.q.NoStart)
}

// Defaults replaces the generic defaults with the operator's configuration,
// which help can only know inside a live service.
func (h *createHandler) Defaults(c config.Config) map[string]string {
	suffix := "; template takes precedence, explicit option overrides both"
	cpus := "unavailable"
	if c.VM.Defaults.CPUs > 0 && c.VM.Defaults.CPUs <= 255 {
		cpus = strconv.FormatUint(c.VM.Defaults.CPUs, 10)
	}
	return map[string]string{
		"cpus":   cpus + suffix,
		"memory": c.VM.Defaults.Memory.String() + suffix,
		"disk":   c.VM.Defaults.Disk.String() + suffix,
		"image":  service.ImageDefaultForHelp(c) + suffix,
	}
}

func (h *createHandler) Run(c *Context, args cmdline.Args) (Result, error) {
	if e := args.NoLiteral(); e != nil {
		return Result{}, e
	}
	if len(args.Positional) > 1 {
		return Result{}, cmdline.Unexpected("IMAGE")
	}
	if len(args.Positional) == 1 {
		if h.image.Seen() {
			return Result{}, usageReason("IMAGE and --image cannot be supplied together")
		}
		if args.Positional[0] == "" {
			return Result{}, usageReason("invalid IMAGE")
		}
		h.q.Image = args.Positional[0]
	}
	// Parsing stays pure; the one option that reads the session does so after.
	h.q.UserdataSet = h.userdata.Seen()
	if h.q.UserdataSet && h.q.Userdata == "-" {
		data, e := c.Document(identity.Create, 16384)
		if e != nil {
			return Result{}, e
		}
		h.q.Userdata = string(data)
	}
	return c.Await(c.Service.Create(c, c.Caller, h.q))
}
