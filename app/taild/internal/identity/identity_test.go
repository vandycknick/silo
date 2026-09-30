package identity

import (
	"encoding/json"
	"testing"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

func TestCapabilities(t *testing.T) {
	defaults := Limits{5, 8, 32 << 30, 200 << 30}
	for _, tt := range []struct {
		name, raw string
		actions   int
		vms       uint64
	}{
		{"absent", `{}`, 0, 0},
		{"single", `{"cap":[{"actions":["vm.read"]}]}`, 1, 5},
		{"additive", `{"cap":[{"actions":["vm.read"],"limits":{"vms":2}},{"actions":["vm.exec"],"limits":{"vms":9,"memory":"64GiB"}}]}`, 2, 9},
		{"star", `{"cap":[{"actions":["*"]}]}`, len(Actions()), 5},
		{"unknown", `{"cap":[{"actions":["future","vm.read"]}]}`, 1, 5},
		{"scope", `{"cap":[{"actions":["*"],"scope":"all"}]}`, 0, 0},
		{"malformed", `{"cap":[{"actions":["vm.read"]},{"actions":"*"}]}`, 0, 0},
		{"bad-size", `{"cap":[{"actions":["vm.read"],"limits":{"memory":"wat"}}]}`, 0, 0},
		{"null", `{"cap":[null]}`, 0, 0},
		{"missing-actions", `{"cap":[{"limits":{"vms":50}}]}`, 0, 0},
		{"null-actions", `{"cap":[{"actions":null}]}`, 0, 0},
		{"null-action-element", `{"cap":[{"actions":["vm.read",null]}]}`, 0, 0},
		{"numeric-action-element", `{"cap":[{"actions":["vm.read",1]}]}`, 0, 0},
		{"null-scope", `{"cap":[{"actions":["vm.read"],"scope":null}]}`, 0, 0},
		{"numeric-scope", `{"cap":[{"actions":["vm.read"],"scope":1}]}`, 0, 0},
		{"null-limits", `{"cap":[{"actions":["vm.read"],"limits":null}]}`, 0, 0},
		{"numeric-limits", `{"cap":[{"actions":["vm.read"],"limits":1}]}`, 0, 0},
		{"array-limits", `{"cap":[{"actions":["vm.read"],"limits":[]}]}`, 0, 0},
		{"future-scope-malformed-actions", `{"cap":[{"actions":["vm.read"]},{"scope":"future","actions":1}]}`, 1, 5},
		{"future-scope-null-fields", `{"cap":[{"actions":["vm.read"]},{"scope":"future","actions":null,"limits":null}]}`, 1, 5},
		{"future-scope-malformed-limits", `{"cap":[{"actions":["vm.read"]},{"scope":"future","actions":[null],"limits":{"vms":-1}}]}`, 1, 5},
		{"malformed-applicable-after-valid", `{"cap":[{"actions":["vm.read"]},{"scope":"own","actions":[null]}]}`, 0, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var caps tailcfg.PeerCapMap
			if e := json.Unmarshal([]byte(tt.raw), &caps); e != nil {
				t.Fatal(e)
			}
			p := ParseCapabilities(caps, "cap", defaults, nil)
			if len(p.Actions) != tt.actions || p.Limits.VMs != tt.vms {
				t.Fatalf("%+v", p)
			}
		})
	}
}

func TestCapabilityLimitTypesAndDefaults(t *testing.T) {
	defaults := Limits{5, 8, 32 << 30, 200 << 30}
	for _, tt := range []struct {
		name, raw string
		want      Limits
	}{
		{"omitted", `{"actions":["vm.read"]}`, defaults},
		{"empty-object", `{"actions":["vm.read"],"scope":"own","limits":{}}`, defaults},
		{"zero-vms", `{"actions":["vm.read"],"limits":{"vms":0}}`, Limits{0, 8, 32 << 30, 200 << 30}},
		{"all-zero", `{"actions":["vm.read"],"limits":{"vms":0,"cpus":0,"memory":"0B","disk":"0GiB"}}`, Limits{}},
		{"additive-default-zero", `{"actions":["vm.read"],"limits":{"vms":0,"cpus":0,"memory":"0B","disk":"0B"}},{"actions":["vm.exec"]}`, defaults},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var caps tailcfg.PeerCapMap
			if err := json.Unmarshal([]byte(`{"cap":[`+tt.raw+`]}`), &caps); err != nil {
				t.Fatal(err)
			}
			p := ParseCapabilities(caps, "cap", defaults, nil)
			if !p.Has(Read) || p.Limits != tt.want {
				t.Fatalf("%+v, want %+v", p, tt.want)
			}
		})
	}
	for _, field := range []string{"vms", "cpus", "memory", "disk"} {
		bad := []string{"null", "true", "{}", "[]"}
		if field == "vms" || field == "cpus" {
			bad = append(bad, `"0"`, "-1", "1.5", "18446744073709551616")
		} else {
			bad = append(bad, "0", "1.5", `"1.5GiB"`)
		}
		for _, value := range bad {
			t.Run(field+"="+value, func(t *testing.T) {
				var caps tailcfg.PeerCapMap
				raw := `{"cap":[{"actions":["vm.read"]},{"scope":"own","actions":["vm.exec"],"limits":{"` + field + `":` + value + `}}]}`
				if err := json.Unmarshal([]byte(raw), &caps); err != nil {
					t.Fatal(err)
				}
				p := ParseCapabilities(caps, "cap", defaults, nil)
				if len(p.Actions) != 0 || p.Limits != (Limits{}) {
					t.Fatalf("malformed field granted access: %+v", p)
				}
			})
		}
	}
}
func TestWhoIsIdentity(t *testing.T) {
	w := &apitype.WhoIsResponse{Node: &tailcfg.Node{StableID: "node-1", Name: "peer"}, UserProfile: &tailcfg.UserProfile{ID: 123, LoginName: "root"}}
	p, e := FromWhoIs(w, "cap", Limits{}, nil)
	if e != nil || len(p.Principals) != 1 || p.Principals[0] != "user:123" {
		t.Fatalf("%+v %v", p, e)
	}
	w.Node.Tags = []string{"tag:ci", "tag:build"}
	w.UserProfile.LoginName = "forged-owner"
	p, e = FromWhoIs(w, "cap", Limits{}, nil)
	if e != nil || len(p.Principals) != 2 || p.Principals[0] != "tag:ci" {
		t.Fatalf("%+v %v", p, e)
	}
	w.Node.Tags = nil
	w.UserProfile.LoginName = "tagged-devices"
	if _, e = FromWhoIs(w, "cap", Limits{}, nil); e == nil {
		t.Fatal("accepted empty tagged identity")
	}
	for _, s := range []string{"", "user:0", "user:01", "user:-1", "tag:../x", "tag:x/y", "user:18446744073709551616"} {
		if _, e := ParsePrincipal(s); e == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}
