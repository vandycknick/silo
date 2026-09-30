package sshd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/service"
)

const Help = "silo · VMs on your tailnet\nPhase 10 lobby: help, whoami [--json], version [--json], exit (interactive only).\nVM commands arrive in subsequent phases.\n"

type response struct {
	OK    bool         `json:"ok"`
	Data  any          `json:"data,omitempty"`
	Error *authz.Error `json:"error,omitempty"`
}

// Dispatch is below authentication. Tests supply explicit domain identity here,
// never a localhost/header bypass to the production WhoIs boundary.
func Dispatch(s *service.Service, p identity.Peer, line string, stdout, stderr io.Writer) int {
	tokens, err := Tokenize(line)
	jsonOutput := false
	if err == nil {
		filtered := []string{}
		for _, t := range tokens {
			if t == "--json" {
				if jsonOutput {
					err = errors.New("duplicate --json")
				}
				jsonOutput = true
			} else {
				filtered = append(filtered, t)
			}
		}
		tokens = filtered
	}
	var data any
	human := ""
	var failure *authz.Error
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
		} else if len(tokens) > 1 {
			failure = &authz.Error{Code: "usage", Message: "unknown argument or option", Exit: 2}
		} else {
			switch tokens[0] {
			case "help":
				data = struct {
					Help string `json:"help"`
				}{Help}
				human = Help
			case "version":
				data = service.Versions()
				human = fmt.Sprintf("taild %s · SDK %s · runtime %s · tailscale 1.102.5\n", service.Versions().Taild, service.Versions().SDK, service.Versions().Runtime)
			case "whoami":
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
				failure = &authz.Error{Code: "usage", Message: "unknown command", Exit: 2}
			}
		}
	}
	if jsonOutput {
		if e := json.NewEncoder(stdout).Encode(response{OK: failure == nil, Data: data, Error: failure}); e != nil {
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
	return 0
}
