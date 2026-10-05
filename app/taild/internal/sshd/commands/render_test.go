package commands

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/service"
	silo "github.com/vandycknick/silo/sdk/go"
)

func TestRenderingSnapshots(t *testing.T) {
	created := time.Date(2026, 10, 2, 12, 34, 56, 0, time.UTC)
	v := service.VM{ID: "vm", Name: "dev", Owner: "user:1", OwnerLogin: "owner@example.test", DefaultUser: "nickvd", State: silo.MachineStatusStopped, CPUs: 2, Memory: 4 * 1024 * 1024 * 1024, Disk: 8 * 1024 * 1024 * 1024, Created: created, Node: "dev.example.ts.net", Address: "100.64.0.1", Image: "ghcr.io/ns/image:tag", Labels: map[string]string{"team": "alpha"}}
	if got := renderListAt([]service.VM{v}, created.Add(time.Hour)); got != "NAME  STATE    NODE                CPUS  MEMORY  CREATED\ndev   stopped  dev.example.ts.net  2     4G      About an hour ago\n" {
		t.Fatal(got)
	}
	want := "Name: dev\nID: vm\nOwner: owner@example.test\nGuest user: nickvd\nState: stopped\nCPUs: 2\nMemory: 4G\nDisk: 8GiB\nCreated: 2026-10-02 12:34:56 UTC\nImage: ghcr.io/ns/image:tag\nLabels:\n  team: alpha\n"
	want += "Node: dev.example.ts.net\nNode state: \nKey expiry: Unavailable\n"
	if got := renderShow(v); got != want {
		t.Fatal(got)
	}
}

func TestShowReadableOptionalFieldsAndExpiry(t *testing.T) {
	v := service.VM{Owner: "tag:owner", OwnerLogin: "creator@example.test", Tags: []string{"tag:dev"}, DefaultUser: "root", KeyExpiry: "never", KeyExpiryLastKnown: true}
	text := renderShow(v)
	if !strings.Contains(text, "Owner: tag:owner\n") || !strings.Contains(text, "Guest user: root\n") || !strings.Contains(text, "Key expiry: Never (last known)\n") || strings.Contains(text, "Labels:") || strings.Contains(text, "Last operation:") || strings.Contains(text, "creator@example") {
		t.Fatal(text)
	}
	v.Labels = map[string]string{"z": "last", "a": "line\n\x1b[2K"}
	text = renderShow(v)
	if !strings.Contains(text, "Labels:\n  a: line��[2K\n  z: last\n") || strings.Contains(text, "map[") {
		t.Fatal(text)
	}
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ value, want string }{{"unknown", "Unavailable"}, {"0001-01-01T00:00:00Z", "Unavailable"}, {"2026-10-05T11:00:00Z", "2026-10-05 11:00:00 UTC (expired) (last known)"}, {"2026-10-06T12:00:00Z", "2026-10-06 12:00:00 UTC (last known)"}} {
		v.KeyExpiry = tc.value
		if got := expiryText(v, now); got != tc.want {
			t.Fatal(got, tc.want)
		}
	}
	b, err := json.Marshal(v)
	if err != nil || strings.Contains(string(b), "last_operation") {
		t.Fatal(string(b), err)
	}
}

func TestHumanRenderingKeepsJSONSizesAndAddresses(t *testing.T) {
	created := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	v := service.VM{Name: "café", Memory: 1536 * 1024 * 1024, Disk: 200_000_000_000, Created: created, Address: "100.64.0.1", Addresses: []string{"100.64.0.1"}}
	for _, text := range []string{renderListAt([]service.VM{v}, created), renderShow(v)} {
		if strings.Contains(text, "ADDRESS") || strings.Contains(text, "Address:") || strings.Contains(text, v.Address) || !strings.Contains(text, "1536M") {
			t.Fatal(text)
		}
	}
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Memory    uint64
		Disk      uint64
		Address   string
		Addresses []string
		Created   time.Time
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Memory != v.Memory || decoded.Disk != v.Disk || decoded.Address != v.Address || len(decoded.Addresses) != 1 || !decoded.Created.Equal(created) {
		t.Fatal(string(data))
	}
	got := renderListAt([]service.VM{v, {Name: "abcde", Node: "pending"}}, created)
	lines := strings.Split(got, "\n")
	if len([]rune(strings.Split(lines[1], "1536M")[0])) != len([]rune(strings.Split(lines[2], "0G")[0])) {
		t.Fatal("unaligned Unicode columns", got)
	}
}
