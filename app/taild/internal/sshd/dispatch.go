package sshd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/service"
)

const Help = "silo · VMs on your tailnet\nhelp, whoami, version, create NAME, ls, show VM, start VM, stop VM, restart VM, rm VM, set VM KEY=VALUE, logs VM, shell VM, exec VM -- CMD..., ops [show ID]\nUse --json for structured queries/mutations. Guest exec arguments after -- are literal. Phase 11 VMs have no tailnet node.\n"

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
func DispatchSession(ctx context.Context, s *service.Service, c service.Caller, line string, streams service.IO) int {
	p := c.Peer
	stdout, stderr := streams.Stdout, streams.Stderr
	tokens, err := Tokenize(line)
	jsonOutput := false
	yes := false
	if err == nil {
		filtered := []string{}
		literal := false
		for _, t := range tokens {
			if t == "--" {
				literal = true
			}
			if t == "--json" && !literal {
				if jsonOutput {
					err = errors.New("duplicate --json")
				}
				jsonOutput = true
			} else if t == "--yes" && !literal {
				yes = true
			} else {
				filtered = append(filtered, t)
			}
		}
		tokens = filtered
	}
	var data any
	human := ""
	var failure *authz.Error
	exit := 0
	if err != nil {
		failure = &authz.Error{Code: "usage", Message: err.Error(), Exit: 2}
	}
	if e := s.CheckIdentity(p); e != nil {
		var denied *authz.Error
		if errors.As(e, &denied) {
			failure = denied
		} else {
			failure = &authz.Error{Code: "unavailable", Message: "service unavailable", Exit: 9}
		}
	}
	if failure == nil {
		if len(tokens) == 0 {
			failure = &authz.Error{Code: "usage", Message: "command required", Exit: 2}
		} else {
			switch tokens[0] {
			case "new":
				tokens[0] = "create"
			case "list":
				tokens[0] = "ls"
			case "status":
				tokens[0] = "show"
			case "ssh":
				tokens[0] = "shell"
			}
			if yes && tokens[0] == "rm" {
				tokens = append(tokens, "--yes")
			}
			switch tokens[0] {
			case "help":
				if len(tokens) > 2 {
					failure = &authz.Error{Code: "usage", Message: "unknown argument or option", Exit: 2}
					break
				}
				help := Help
				if len(tokens) == 2 {
					var ok bool
					help, ok = commandHelp(tokens[1])
					if !ok {
						failure = &authz.Error{Code: "usage", Message: "unknown command", Exit: 2}
						break
					}
				}
				data = struct {
					Help string `json:"help"`
				}{help}
				human = help
			case "version":
				if len(tokens) != 1 {
					failure = &authz.Error{Code: "usage", Message: "unknown argument or option", Exit: 2}
					break
				}
				data = service.Versions()
				human = fmt.Sprintf("taild %s · SDK %s · runtime %s · tailscale 1.102.5\n", service.Versions().Taild, service.Versions().SDK, service.Versions().Runtime)
			case "whoami":
				if len(tokens) != 1 {
					failure = &authz.Error{Code: "usage", Message: "unknown argument or option", Exit: 2}
					break
				}
				var who service.WhoAmI
				who, err = s.WhoAmI(p)
				if err != nil {
					var e *authz.Error
					if errors.As(err, &e) {
						failure = e
					} else {
						failure = &authz.Error{Code: "unavailable", Message: "service unavailable", Exit: 9}
					}
				} else {
					data = who
					human = fmt.Sprintf("Principals: %v\nNode: %s (%s)\nActions: %v (scope own)\n", p.Principals, p.NodeName, p.NodeID, p.Permissions.Actions)
					if who.Explanation != "" {
						human += who.Explanation + ". Ask your tailnet admin for " + s.Capability + ".\n"
					}
				}
			default:
				data, human, exit, err = commands(ctx, s, c, tokens, jsonOutput, streams)
				failure = service.Categorize(err)
			}
		}
	}
	if jsonOutput {
		var wireError *responseError
		if failure != nil {
			wireError = &responseError{Code: failure.Code, Message: failure.Message}
			if op, ok := data.(jobs.Operation); ok {
				wireError.Operation = op.ID
			}
		}
		if e := json.NewEncoder(stdout).Encode(response{OK: failure == nil, Data: data, Error: wireError}); e != nil {
			return 255
		}
	}
	if failure != nil {
		_, _ = fmt.Fprintln(stderr, "Error:", failure.Message)
		return failure.Exit
	}
	if !jsonOutput {
		_, err = io.Copy(stderr, strings.NewReader(human))
		if err != nil {
			return 255
		}
	}
	return exit
}
