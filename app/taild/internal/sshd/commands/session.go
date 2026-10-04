package commands

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/service"
)

// Await relays operation progress to the human stream until it finishes. The
// subscription belongs to this session; the operation belongs to jobs and
// keeps running if the session disconnects.
func (c *Context) Await(op jobs.Operation, err error) (Result, error) {
	if err != nil {
		return Result{}, err
	}
	out := c.Streams.HumanWriter()
	reported := 0
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		current, changed, e := c.Service.Jobs.Observe(c.Caller.Peer, op.ID)
		if e != nil {
			return Result{}, e
		}
		if reported > len(current.Progress) {
			reported = 0
		}
		for _, line := range current.Progress[reported:] {
			if _, e := fmt.Fprintln(out, line); e != nil {
				return Result{}, e
			}
		}
		reported = len(current.Progress)
		if current.Finished != nil {
			if current.Error != nil {
				return Result{Data: current}, current.Error
			}
			message := current.Kind + " succeeded\n"
			if current.Kind == "create" {
				message = "create " + current.VM + " succeeded\n"
			}
			return Result{Data: current, Human: message}, nil
		}
		select {
		case <-c.Done():
			return Result{Data: op}, &authz.Error{Code: "disconnected", Message: "observer closed; operation continues", Exit: 255}
		case <-changed:
		case <-ticker.C:
			p, e := c.Caller.Fresh(c)
			if e != nil || !p.Owns(current.Principal) {
				return Result{}, &authz.Error{Code: "forbidden", Message: "operation observer authorization lost", Exit: 4}
			}
			c.Caller.Peer = p
		}
	}
}

// Document reads one bounded document from the session input, with a deadline
// so a silent peer cannot park a session in the daemon forever. The peer must
// hold the action before the daemon consumes any of its bytes.
func (c *Context) Document(action identity.Action, limit int) ([]byte, error) {
	if e := c.Service.Authorize(c.Caller.Peer, action, nil); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(c, 30*time.Second)
	defer cancel()
	src := c.Streams.Stdin
	if c.Streams.Input != nil {
		src = c.Streams.Input(ctx)
	}
	if src == nil {
		return nil, Usage()
	}
	data, e := io.ReadAll(io.LimitReader(src, int64(limit)+1))
	if e != nil {
		return nil, usageReason("document input interrupted or timed out")
	}
	if len(data) > limit {
		return nil, usageReason("document input exceeds size limit")
	}
	return data, nil
}

// Confirm asks the peer to approve a removal. Anything but an explicit yes,
// including a session without a prompt, is a no.
func (c *Context) Confirm(target service.RemovalTarget) bool {
	if c.Streams.Prompt == nil {
		return false
	}
	verb := "Remove"
	if target.Running {
		verb = "Stop and remove"
	}
	prompt := fmt.Sprintf("%s VM '%s'? [y/N] ", verb, target.Name)
	for c.Err() == nil {
		line, e := c.Streams.Prompt(c, prompt, 1024)
		if e != nil || c.Err() != nil {
			return false
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return true
		case "", "n", "no":
			return false
		}
	}
	return false
}
