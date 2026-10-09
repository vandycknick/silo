package sshd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/sshd/commands"
)

type response struct {
	OK    bool           `json:"ok"`
	Data  any            `json:"data,omitempty"`
	Error *responseError `json:"error,omitempty"`
}
type responseError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Operation string `json:"operation,omitempty"`
}

// DispatchSession runs one command line: tokenize, check identity, hand the
// tokens to the command package, and encode its result for this session.
func DispatchSession(ctx context.Context, s *service.Service, caller service.Caller, line string, streams service.IO) int {
	c := &commands.Context{Context: ctx, Service: s, Caller: caller, Streams: normalizeHuman(streams)}
	tokens, err := Tokenize(line)
	var result commands.Result
	// Identity outranks syntax: an unverified peer learns nothing about parsing.
	failure := service.Categorize(s.CheckIdentity(caller.Peer))
	switch {
	case failure != nil:
	case err != nil:
		failure = &authz.Error{Code: "usage", Message: err.Error(), Exit: 2}
	default:
		result, err = commands.Execute(c, tokens)
		failure = service.Categorize(err)
	}
	return respond(c, result, failure)
}

// respond writes the JSON envelope to stdout when requested, and the human
// rendering or error line to the human stream. Transport failures exit 255.
func respond(c *commands.Context, r commands.Result, failure *authz.Error) int {
	if c.JSON {
		var wire *responseError
		if failure != nil {
			wire = &responseError{Code: failure.Code, Message: failure.Message}
			if op, ok := r.Data.(jobs.Operation); ok {
				wire.Operation = op.ID
			}
		}
		if e := json.NewEncoder(c.Streams.Stdout).Encode(response{OK: failure == nil, Data: r.Data, Error: wire}); e != nil {
			return 255
		}
	}
	out := c.Streams.HumanWriter()
	if failure != nil {
		if _, e := fmt.Fprintln(out, "Error:", failure.Message); e != nil {
			return 255
		}
		return failure.Exit
	}
	if !c.JSON {
		if _, e := io.WriteString(out, r.Human); e != nil {
			return 255
		}
	}
	return r.Exit
}
