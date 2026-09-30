// Package identity models verified WhoIs observations and own-scope grants.
package identity

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/units"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

type Principal string

func ParsePrincipal(s string) (Principal, error) {
	if strings.HasPrefix(s, "user:") {
		n, e := strconv.ParseUint(s[5:], 10, 64)
		if e == nil && n > 0 && strconv.FormatUint(n, 10) == s[5:] {
			return Principal(s), nil
		}
	}
	if strings.HasPrefix(s, "tag:") && regexp.MustCompile(`^tag:[a-zA-Z][a-zA-Z0-9-]*$`).MatchString(s) {
		return Principal(s), nil
	}
	return "", errors.New("invalid principal")
}

type Action string

const (
	Create         Action = "vm.create"
	Read           Action = "vm.read"
	Start          Action = "vm.start"
	Stop           Action = "vm.stop"
	Delete         Action = "vm.delete"
	Shell          Action = "vm.shell"
	Exec           Action = "vm.exec"
	Logs           Action = "vm.logs"
	Update         Action = "vm.update"
	TemplateManage Action = "template.manage"
	Restart        Action = "vm.restart"
	Reauth         Action = "vm.reauth"
)

func Actions() []Action {
	return []Action{Create, Read, Start, Stop, Delete, Shell, Exec, Logs, Update, TemplateManage}
}

type Limits struct {
	VMs    uint64 `json:"vms"`
	CPUs   uint64 `json:"cpus"`
	Memory uint64 `json:"memory"`
	Disk   uint64 `json:"disk"`
}
type Permissions struct {
	Actions []Action `json:"actions"`
	Limits  Limits   `json:"limits"`
	Reason  string   `json:"reason,omitempty"`
}

func (p Permissions) Has(a Action) bool { return slices.Contains(p.Actions, a) }

type Peer struct {
	Principals  []Principal `json:"principals"`
	NodeID      string      `json:"node_id"`
	NodeName    string      `json:"node_name"`
	Login       string      `json:"login,omitempty"`
	ObservedAt  time.Time   `json:"observed_at"`
	Permissions Permissions `json:"permissions"`
}

func (p Peer) Valid() bool {
	if len(p.Principals) == 0 || p.NodeID == "" || p.ObservedAt.IsZero() {
		return false
	}
	for _, v := range p.Principals {
		if _, e := ParsePrincipal(string(v)); e != nil {
			return false
		}
	}
	return true
}
func (p Peer) Owns(owner Principal) bool { return slices.Contains(p.Principals, owner) }

func FromWhoIs(w *apitype.WhoIsResponse, capability string, defaults Limits, log *slog.Logger) (Peer, error) {
	if w == nil || w.Node == nil || w.UserProfile == nil || w.Node.StableID == "" {
		return Peer{}, errors.New("WhoIs returned no identity")
	}
	p := Peer{NodeID: string(w.Node.StableID), NodeName: w.Node.Name, Login: w.UserProfile.LoginName, ObservedAt: time.Now().UTC()}
	// Node tags, never usernames or display labels, determine tagged identity.
	if len(w.Node.Tags) > 0 {
		for _, tag := range w.Node.Tags {
			v, e := ParsePrincipal(tag)
			if e != nil {
				return Peer{}, e
			}
			if !slices.Contains(p.Principals, v) {
				p.Principals = append(p.Principals, v)
			}
		}
	} else {
		if w.UserProfile.LoginName == "tagged-devices" {
			return Peer{}, errors.New("tagged peer has no tags")
		}
		v, e := ParsePrincipal(fmt.Sprintf("user:%d", w.UserProfile.ID))
		if e != nil {
			return Peer{}, e
		}
		p.Principals = []Principal{v}
	}
	p.Permissions = ParseCapabilities(w.CapMap, capability, defaults, log)
	return p, nil
}

type grant struct {
	Actions []string `json:"actions"`
	Limits  struct {
		VMs    *uint64 `json:"vms"`
		CPUs   *uint64 `json:"cpus"`
		Memory *string `json:"memory"`
		Disk   *string `json:"disk"`
	} `json:"limits"`
}

// Decode scope first: an entry for a future scope has no meaning in this
// version, including its action/limit schema. Applicable entries are strict
// about JSON types; omitted optional fields differ from explicit nulls.
func parseGrant(raw json.RawMessage) (grant, bool, error) {
	var fields map[string]json.RawMessage
	if err := decodeGrantField(raw, &fields); err != nil {
		return grant{}, false, err
	}
	if rawScope, present := fields["scope"]; present {
		var scope string
		if err := decodeGrantField(rawScope, &scope); err != nil {
			return grant{}, false, err
		}
		if scope != "own" {
			return grant{}, false, nil
		}
	}
	var g grant
	rawActions, present := fields["actions"]
	if !present {
		return grant{}, false, errors.New("actions are required")
	}
	var actions []json.RawMessage
	if err := decodeGrantField(rawActions, &actions); err != nil {
		return grant{}, false, err
	}
	if len(actions) == 0 {
		return grant{}, false, errors.New("actions must not be empty")
	}
	for _, rawAction := range actions {
		var action string
		if err := decodeGrantField(rawAction, &action); err != nil {
			return grant{}, false, err
		}
		g.Actions = append(g.Actions, action)
	}
	if rawLimits, present := fields["limits"]; present {
		var limits map[string]json.RawMessage
		if err := decodeGrantField(rawLimits, &limits); err != nil {
			return grant{}, false, err
		}
		for _, field := range []struct {
			name string
			dest any
		}{
			{"vms", &g.Limits.VMs}, {"cpus", &g.Limits.CPUs},
			{"memory", &g.Limits.Memory}, {"disk", &g.Limits.Disk},
		} {
			if value, present := limits[field.name]; present {
				if err := decodeGrantField(value, field.dest); err != nil {
					return grant{}, false, err
				}
			}
		}
	}
	return g, true, nil
}

func decodeGrantField(raw json.RawMessage, dest any) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("capability fields must not be null")
	}
	return json.Unmarshal(raw, dest)
}

func ParseCapabilities(caps tailcfg.PeerCapMap, name string, defaults Limits, log *slog.Logger) Permissions {
	denied := Permissions{Actions: []Action{}, Reason: "No valid own-scope taild capability was granted"}
	entries, e := tailcfg.UnmarshalCapJSON[json.RawMessage](caps, tailcfg.PeerCapability(name))
	if e != nil {
		denied.Reason = "Malformed taild capability"
		return denied
	}
	result := denied
	for _, rawEntry := range entries {
		g, applicable, err := parseGrant(rawEntry)
		if err != nil {
			denied.Reason = "Malformed taild capability"
			return denied
		}
		if !applicable {
			continue
		}
		l := defaults
		if g.Limits.VMs != nil {
			l.VMs = *g.Limits.VMs
		}
		if g.Limits.CPUs != nil {
			l.CPUs = *g.Limits.CPUs
		}
		for _, field := range []struct {
			value *string
			dest  *uint64
		}{{g.Limits.Memory, &l.Memory}, {g.Limits.Disk, &l.Disk}} {
			if field.value != nil {
				n, err := units.Bytes(*field.value)
				if err != nil {
					return denied
				}
				*field.dest = n
			}
		}
		for _, raw := range g.Actions {
			expanded := []Action{Action(raw)}
			if raw == "*" {
				expanded = Actions()
			}
			for _, a := range expanded {
				if !slices.Contains(Actions(), a) {
					if log != nil {
						log.Info("ignoring unknown capability action", "action", a)
					}
					continue
				}
				if !result.Has(a) {
					result.Actions = append(result.Actions, a)
				}
			}
		}
		result.Limits.VMs = max(result.Limits.VMs, l.VMs)
		result.Limits.CPUs = max(result.Limits.CPUs, l.CPUs)
		result.Limits.Memory = max(result.Limits.Memory, l.Memory)
		result.Limits.Disk = max(result.Limits.Disk, l.Disk)
	}
	slices.Sort(result.Actions)
	if len(result.Actions) > 0 {
		result.Reason = ""
	}
	return result
}
