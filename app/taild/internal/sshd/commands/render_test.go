package commands

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/service"
	silo "github.com/vandycknick/silo/sdk/go"
)

func TestRenderingSnapshots(t *testing.T) {
	created := time.Date(2026, 10, 2, 12, 34, 56, 0, time.UTC)
	v := service.VM{ID: "vm", Name: "dev", Owner: "user:1", State: silo.MachineStatusStopped, CPUs: 2, Memory: 4 * 1024 * 1024 * 1024, Disk: 8 * 1024 * 1024 * 1024, Created: created, Node: "dev.example.ts.net", Address: "100.64.0.1", Image: "ghcr.io/ns/image:tag", Labels: map[string]string{"team": "alpha"}, LastOperation: &jobs.Operation{ID: "op_00000000000000000000000000", State: "succeeded"}}
	if got := renderListAt([]service.VM{v}, created.Add(time.Hour)); got != "NAME  STATE    NODE                CPUS  MEMORY  CREATED\ndev   stopped  dev.example.ts.net  2     4G      About an hour ago\n" {
		t.Fatal(got)
	}
	want := "Name: dev\nID: vm\nOwner: user:1\nState: stopped\nCPUs: 2\nMemory: 4G\nDisk: 8GiB\nCreated: 2026-10-02 12:34:56 UTC\nImage: ghcr.io/ns/image:tag\nLabels: map[team:alpha]\nLast operation: op_00000000000000000000000000 succeeded\n"
	want += "Node: dev.example.ts.net\nNode state: \nKey expiry: \n"
	if got := renderShow(v); got != want {
		t.Fatal(got)
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
