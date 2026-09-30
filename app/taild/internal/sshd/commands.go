package sshd

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/units"
	silo "github.com/vandycknick/silo/sdk/go"
)

func usage() error {
	return &authz.Error{Code: "usage", Message: "invalid command arguments; see help", Exit: 2}
}
func size(s string) (uint64, error) {
	v, e := units.Bytes(s)
	if e != nil || v <= 0 {
		return 0, usage()
	}
	return uint64(v), nil
}
func commands(ctx context.Context, s *service.Service, c service.Caller, t []string, jsonOutput bool, streams service.IO) (any, string, int, error) {
	cmd := t[0]
	args := t[1:]
	var op jobs.Operation
	var err error
	switch cmd {
	case "ls":
		if len(args) != 0 {
			return nil, "", 2, usage()
		}
		v, e := s.List(ctx, c.Peer)
		return v, renderList(v), 0, e
	case "show":
		if len(args) != 1 {
			return nil, "", 2, usage()
		}
		v, e := s.Show(ctx, c.Peer, args[0])
		return v, renderShow(v), 0, e
	case "ops":
		id := ""
		if len(args) != 0 {
			if len(args) != 2 || args[0] != "show" {
				return nil, "", 2, usage()
			}
			id = args[1]
		}
		ops, e := s.Ops(c.Peer, id)
		var b strings.Builder
		for _, op := range ops {
			fmt.Fprintf(&b, "%s %s %s %s\n", op.ID, op.Kind, op.VM, op.State)
		}
		return ops, b.String(), 0, e
	case "create":
		if len(args) == 0 {
			return nil, "", 2, usage()
		}
		q := service.CreateRequest{Name: args[0], Labels: map[string]string{}}
		seen := map[string]bool{}
		start := 1
		if len(args) > 1 && !strings.HasPrefix(args[1], "--") {
			q.Image = args[1]
			seen["--image"] = true
			start = 2
		}
		for i := start; i < len(args); i++ {
			key := args[i]
			if key == "--disk-size" {
				key = "--disk"
			}
			if key != "--label" && seen[key] {
				return nil, "", 2, usage()
			}
			seen[key] = true
			switch key {
			case "--no-tailnet":
				q.NoTailnet = true
			case "--no-start":
				q.NoStart = true
			default:
				if i+1 >= len(args) {
					return nil, "", 2, usage()
				}
				i++
				v := args[i]
				switch key {
				case "--image":
					q.Image = v
				case "--owner":
					q.Owner = identity.Principal(v)
				case "--cpus":
					q.CPUs, err = strconv.ParseUint(v, 10, 64)
					if q.CPUs == 0 {
						err = usage()
					}
				case "--memory":
					q.Memory, err = size(v)
				case "--disk":
					q.Disk, err = size(v)
				case "--userdata":
					if v == "-" {
						if streams.Stdin == nil {
							return nil, "", 2, usage()
						}
						if e := s.Authorize(c.Peer, identity.Create, nil); e != nil {
							return nil, "", 4, e
						}
						data, e := io.ReadAll(io.LimitReader(streams.Stdin, 16385))
						if e != nil {
							return nil, "", 255, e
						}
						if len(data) > 16384 {
							return nil, "", 2, usage()
						}
						q.Userdata = string(data)
					} else {
						q.Userdata = v
					}
				case "--label":
					k, value, ok := strings.Cut(v, "=")
					if !ok {
						err = usage()
					} else if _, ok = q.Labels[k]; ok {
						err = usage()
					} else {
						q.Labels[k] = value
					}
				default:
					err = usage()
				}
				if err != nil {
					return nil, "", 2, usage()
				}
			}
		}
		op, err = s.Create(ctx, c, q)
	case "start", "restart":
		if len(args) != 1 {
			return nil, "", 2, usage()
		}
		if cmd == "start" {
			op, err = s.Start(ctx, c, args[0])
		} else {
			op, err = s.Restart(ctx, c, args[0])
		}
	case "stop":
		if len(args) == 0 {
			return nil, "", 2, usage()
		}
		q := service.StopRequest{}
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--force":
				q.Force = true
			case "--timeout":
				if i+1 >= len(args) {
					return nil, "", 2, usage()
				}
				i++
				q.Timeout, err = time.ParseDuration(args[i])
				if err != nil {
					return nil, "", 2, usage()
				}
			default:
				return nil, "", 2, usage()
			}
		}
		op, err = s.Stop(ctx, c, args[0], q)
	case "rm":
		if len(args) == 0 {
			return nil, "", 2, usage()
		}
		q := service.RemoveRequest{Confirmed: jsonOutput}
		for _, arg := range args[1:] {
			switch arg {
			case "--force":
				q.Force = true
			case "--yes":
				q.Confirmed = true
			default:
				return nil, "", 2, usage()
			}
		}
		if !q.Confirmed && streams.Terminal.Present && streams.Stdin != nil {
			_, _ = fmt.Fprintf(streams.Stderr, "Remove %s? Type yes: ", args[0])
			line, e := readLineLimit(streams.Stdin, 1024)
			if e == nil {
				q.Confirmed = line == "yes"
			}
		}
		op, err = s.Remove(ctx, c, args[0], q)
	case "set":
		if len(args) < 2 {
			return nil, "", 2, usage()
		}
		q := service.SetRequest{}
		seen := map[string]bool{}
		for _, arg := range args[1:] {
			k, v, ok := strings.Cut(arg, "=")
			if !ok || seen[k] {
				return nil, "", 2, usage()
			}
			seen[k] = true
			switch k {
			case "name":
				q.Name = &v
			case "cpus":
				n, e := strconv.ParseUint(v, 10, 8)
				if e != nil || n == 0 {
					return nil, "", 2, usage()
				}
				n8 := uint8(n)
				q.CPUs = &n8
			case "memory", "disk":
				n, e := size(v)
				if e != nil {
					return nil, "", 2, e
				}
				b := silo.Bytes(n)
				if k == "memory" {
					q.Memory = &b
				} else {
					q.Disk = &b
				}
			default:
				return nil, "", 2, usage()
			}
		}
		op, err = s.Set(ctx, c, args[0], q)
	case "shell", "exec":
		if jsonOutput || len(args) == 0 {
			return nil, "", 2, usage()
		}
		q := service.ExecRequest{Env: map[string]string{}}
		delimiter := false
		for i := 1; i < len(args); i++ {
			key := args[i]
			if key == "--" {
				if cmd != "exec" || i+1 >= len(args) {
					return nil, "", 2, usage()
				}
				q.Program = args[i+1]
				q.Args = args[i+2:]
				delimiter = true
				break
			}
			if key == "-t" && cmd == "exec" {
				q.TTY = true
				continue
			}
			if i+1 >= len(args) {
				return nil, "", 2, usage()
			}
			i++
			v := args[i]
			switch key {
			case "-u":
				q.User = v
			case "-w":
				if cmd != "exec" {
					return nil, "", 2, usage()
				}
				q.Directory = v
			case "-e":
				if cmd != "exec" {
					return nil, "", 2, usage()
				}
				k, v, ok := strings.Cut(v, "=")
				if !ok {
					return nil, "", 2, usage()
				}
				q.Env[k] = v
			default:
				return nil, "", 2, usage()
			}
		}
		var code int
		if cmd == "shell" {
			code, err = s.Shell(ctx, c, args[0], q.User, streams)
		} else {
			if !delimiter {
				return nil, "", 2, usage()
			}
			code, err = s.Exec(ctx, c, args[0], q, streams)
		}
		return nil, "", code, err
	case "logs":
		if jsonOutput || len(args) == 0 {
			return nil, "", 2, usage()
		}
		q := service.LogsRequest{}
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--follow":
				q.Follow = true
			case "--stream", "--output":
				key := args[i]
				if i+1 >= len(args) {
					return nil, "", 2, usage()
				}
				i++
				if key == "--stream" {
					q.Source = silo.MachineLogSource(args[i])
					if args[i] == "network-audit" {
						q.Source = silo.MachineLogNetworkAudit
					}
				} else {
					q.Output = silo.MachineLogOutput(args[i])
				}
			default:
				return nil, "", 2, usage()
			}
		}
		return nil, "", 0, s.Logs(ctx, c, args[0], q, streams.Stdout)
	default:
		return nil, "", 2, usage()
	}
	if err != nil {
		return nil, "", service.Categorize(err).Exit, err
	}
	// The subscription belongs to the session; the operation belongs to jobs.
	progress := 0
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		current, changed, e := s.Jobs.Observe(c.Peer, op.ID)
		if e != nil {
			return nil, "", 3, e
		}
		if progress > len(current.Progress) {
			progress = 0
		}
		for _, line := range current.Progress[progress:] {
			_, _ = fmt.Fprintln(streams.Stderr, line)
		}
		progress = len(current.Progress)
		if current.Finished != nil {
			if current.Error != nil {
				return current, "", current.Error.Exit, current.Error
			}
			return current, current.ID + " succeeded\n", 0, nil
		}
		select {
		case <-ctx.Done():
			return op, "", 255, &authz.Error{Code: "disconnected", Message: "observer closed; operation continues", Exit: 255}
		case <-changed:
		case <-ticker.C:
			p, e := c.Fresh(ctx)
			if e != nil || !p.Owns(current.Principal) {
				return nil, "", 4, &authz.Error{Code: "forbidden", Message: "operation observer authorization lost", Exit: 4}
			}
			c.Peer = p
		}
	}
}
