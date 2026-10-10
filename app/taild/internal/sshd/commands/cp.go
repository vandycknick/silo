package commands

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/sshd/cmdline"
)

var cp = Command{
	Name: "cp", Summary: "Copy a regular file between this session and a VM.", Usage: "cp [OPTIONS] SRC DST",
	Arguments: "SRC  - (stdin) or VM:/absolute/path.\nDST  - (stdout) or VM:/absolute/path.",
	Example:   "ssh silo cp - devbox:/root/patch.diff < patch.diff\nssh silo cp devbox:/root/shot.png - > shot.png\nssh silo cp -p --mode 0755 - devbox:/opt/bin/tool < tool",
	Streaming: true, New: func() Handler { return &cpHandler{} },
}

type endpoint struct {
	Stdio    bool
	VM, Path string
}

func parseEndpoint(s string) (endpoint, error) {
	if s == "-" {
		return endpoint{Stdio: true}, nil
	}
	if strings.HasPrefix(s, "./") || strings.HasPrefix(s, "/") || !strings.Contains(s, ":") {
		return endpoint{Path: s}, nil
	}
	vm, path, _ := strings.Cut(s, ":")
	if vm == "" || strings.Contains(path, ":") {
		return endpoint{}, fmt.Errorf("ambiguous endpoint; use VM:/absolute/path or prefix a local path with ./")
	}
	if !strings.HasPrefix(path, "/") {
		return endpoint{}, fmt.Errorf("guest paths must be absolute (VM:/path)")
	}
	return endpoint{VM: vm, Path: path}, nil
}

type cpHandler struct{ q service.CopyRequest }

func parseOctalMode(s string) (uint32, error) {
	if s == "" || strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '7' }) >= 0 {
		return 0, fmt.Errorf("mode must be octal (0000-7777)")
	}
	n, e := strconv.ParseUint(s, 8, 32)
	if e != nil || n > 07777 {
		return 0, fmt.Errorf("mode must be octal (0000-7777)")
	}
	return uint32(n), nil
}
func parseOwner(s string) (uint32, *uint32, error) {
	uid, gid, hasGID := strings.Cut(s, ":")
	parse := func(v string) (uint32, error) {
		if v == "" || strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return 0, fmt.Errorf("owner must be numeric UID[:GID]")
		}
		n, e := strconv.ParseUint(v, 10, 32)
		if e != nil {
			return 0, fmt.Errorf("owner must be numeric UID[:GID]")
		}
		return uint32(n), nil
	}
	u, e := parse(uid)
	if e != nil {
		return 0, nil, e
	}
	if !hasGID {
		return u, nil, nil
	}
	g, e := parse(gid)
	if e != nil {
		return 0, nil, e
	}
	return u, &g, nil
}
func (h *cpHandler) Flags(f *cmdline.FlagSet) {
	f.Value("mode", "OCTAL", "File mode for uploads.", func(s string) error {
		n, e := parseOctalMode(s)
		if e == nil {
			h.q.Mode = &n
		}
		return e
	}).Default("0644 for new files; preserve on replace")
	f.Value("owner", "UID[:GID]", "Numeric owner for uploads.", func(s string) error {
		u, g, e := parseOwner(s)
		if e == nil {
			h.q.UID, h.q.GID = &u, g
		}
		return e
	}).Default("unchanged")
	f.Alias("parents", f.Bool("p", "Create missing parent directories.", &h.q.Parents))
	f.Alias("no-clobber", f.Bool("n", "Fail if the destination exists (best effort, not atomic).", &h.q.NoClobber))
}
func (h *cpHandler) Run(c *Context, args cmdline.Args) (Result, error) {
	if args.Delimited {
		return Result{}, usageReason("cp does not accept literal arguments after --")
	}
	if len(args.Positional) != 2 {
		return Result{}, usageReason("cp requires SRC and DST")
	}
	src, e := parseEndpoint(args.Positional[0])
	if e != nil {
		return Result{}, usageReason(e.Error())
	}
	dst, e := parseEndpoint(args.Positional[1])
	if e != nil {
		return Result{}, usageReason(e.Error())
	}
	if (!src.Stdio && src.VM == "") || (!dst.Stdio && dst.VM == "") {
		return Result{}, usageReason("the lobby has no access to your files; use - and redirect stdin/stdout")
	}
	if src.VM != "" && dst.VM != "" {
		return Result{}, usageReason("cp copies between the host and one VM")
	}
	if src.VM == "" && dst.VM == "" {
		return Result{}, usageReason("cp requires a VM endpoint (VM:/path)")
	}
	if dst.VM != "" {
		h.q.VM, h.q.Path, h.q.Upload = dst.VM, dst.Path, true
		source := c.Streams.Stdin
		if c.Streams.Input != nil {
			source = c.Streams.Input(c)
		}
		summary, e := c.Service.CopyToVM(c, c.Caller, h.q, source)
		if e != nil {
			return Result{}, e
		}
		return Result{Human: fmt.Sprintf("copied %d bytes to %s:%s (%s, sha256 %s)\n", summary.Bytes, dst.VM, dst.Path, summary.Disposition, summary.SHA256)}, nil
	}
	if h.q.Mode != nil || h.q.UID != nil || h.q.Parents || h.q.NoClobber {
		return Result{}, usageReason("--mode, --owner, --parents and --no-clobber are upload-only")
	}
	h.q.VM, h.q.Path = src.VM, src.Path
	summary, e := c.Service.CopyFromVM(c, c.Caller, h.q, c.Streams.Stdout)
	if e != nil {
		return Result{}, e
	}
	return Result{Human: fmt.Sprintf("copied %d bytes from %s:%s (sha256 %s)\n", summary.Bytes, src.VM, src.Path, summary.SHA256)}, nil
}
