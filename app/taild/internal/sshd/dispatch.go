package sshd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/service"
)

func HelpText() string { return generalHelp() }

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

// Dispatch is below authentication. Tests supply explicit domain identity here,
// never a localhost/header bypass to the production WhoIs boundary.
func Dispatch(s *service.Service, p identity.Peer, line string, stdout, stderr io.Writer) int {
	return DispatchSession(context.Background(), s, service.Caller{Peer: p}, line, service.IO{Stdout: stdout, Stderr: stderr})
}

// DispatchSession runs one command line: tokenize, strip session-wide flags,
// check identity, hand the rest to the command's handler, and encode its reply.
func DispatchSession(ctx context.Context, s *service.Service, c service.Caller, line string, streams service.IO) int {
	streams = normalizeHuman(streams)
	iv := &invocation{ctx: ctx, service: s, caller: c, streams: streams}
	tokens, err := Tokenize(line)
	if err == nil {
		tokens, err = iv.globals(tokens)
	}
	var result reply
	// Identity outranks syntax: an unverified peer learns nothing about parsing.
	failure := service.Categorize(s.CheckIdentity(c.Peer))
	switch {
	case failure != nil:
	case err != nil:
		failure = &authz.Error{Code: "usage", Message: err.Error(), Exit: 2}
	case len(tokens) == 0 && iv.help:
		result, err = runHelp(iv, nil)
	case len(tokens) == 0:
		failure = &authz.Error{Code: "usage", Message: "command required", Exit: 2}
	default:
		name := tokens[0]
		if canonical, ok := aliases[name]; ok {
			name = canonical
		}
		cmd, ok := commands[name]
		if !ok {
			failure = usage()
			break
		}
		if iv.help {
			path := []string{name}
			if (name == "template" || name == "policy" || name == "ops") && len(tokens) > 1 && !isFlag(tokens[1]) {
				path = append(path, tokens[1])
			}
			result, err = runHelp(iv, path)
		} else if iv.json && !acceptsJSON(name) {
			err = usageReason("--json is not supported by this command")
		} else {
			result, err = cmd.run(iv, tokens[1:])
		}
		failure = service.Categorize(err)
	}
	return iv.respond(result, failure)
}

// globals strips the flags every command accepts. Tokens after the literal
// guest delimiter are never interpreted.
func (iv *invocation) globals(tokens []string) ([]string, error) {
	kept := make([]string, 0, len(tokens))
	command := ""
	for _, t := range tokens {
		if !isFlag(t) {
			command = canonicalCommand(t)
			break
		}
	}
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		switch t {
		case "--":
			return append(kept, tokens[i:]...), nil
		case "--json":
			if iv.json {
				return nil, usageReason("duplicate --json")
			}
			iv.json = true
		case "--yes":
			if command == "rm" {
				if iv.yes {
					return nil, usageReason("duplicate --yes")
				}
				iv.yes = true
			} else {
				kept = append(kept, t)
			}
		case "-h", "--help":
			iv.help = true
		default:
			kept = append(kept, t)
			name, _, inline := strings.Cut(strings.TrimLeft(t, "-"), "=")
			if isFlag(t) && !inline && optionTakesValue(command, name) && i+1 < len(tokens) {
				i++
				kept = append(kept, tokens[i])
			}
		}
	}
	return kept, nil
}

// respond writes the JSON envelope to stdout when requested, and the human
// rendering or error line to the human stream. Transport failures exit 255.
func (iv *invocation) respond(r reply, failure *authz.Error) int {
	if iv.json {
		var wire *responseError
		if failure != nil {
			wire = &responseError{Code: failure.Code, Message: failure.Message}
			if op, ok := r.data.(jobs.Operation); ok {
				wire.Operation = op.ID
			}
		}
		if e := json.NewEncoder(iv.streams.Stdout).Encode(response{OK: failure == nil, Data: r.data, Error: wire}); e != nil {
			return 255
		}
	}
	out := humanOutput(iv.streams)
	if failure != nil {
		if _, e := fmt.Fprintln(out, "Error:", failure.Message); e != nil {
			return 255
		}
		return failure.Exit
	}
	if !iv.json {
		if _, e := io.WriteString(out, r.human); e != nil {
			return 255
		}
	}
	return r.exit
}
