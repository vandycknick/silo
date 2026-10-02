package sshd

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/service"
)

func renderList(vms []service.VM) string {
	return renderListAt(vms, time.Now())
}

func renderListAt(vms []service.VM, now time.Time) string {
	var b strings.Builder
	table := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "NAME\tSTATE\tNODE\tCPUS\tMEMORY\tCREATED")
	for _, vm := range vms {
		node := vm.Node
		if node == "" {
			node = string(vm.NodeState)
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%d\t%s\t%s\n", vm.Name, vm.State, node, vm.CPUs, humanMemory(vm.Memory), relativeTime(vm.Created, now))
	}
	_ = table.Flush()
	for _, vm := range vms {
		if vm.ApprovalURL != "" && vm.ApprovalExpires != nil {
			fmt.Fprintf(&b, "Approve %s: %s (expires %s)\n", vm.Name, vm.ApprovalURL, vm.ApprovalExpires.Format(time.RFC3339))
		}
	}
	return b.String()
}
func renderShow(v service.VM) string {
	text := fmt.Sprintf("Name: %s\nID: %s\nOwner: %s\nState: %s\nCPUs: %d\nMemory: %s\nDisk: %s\nCreated: %s\nImage: %s\nLabels: %v\n", v.Name, v.ID, v.Owner, v.State, v.CPUs, humanMemory(v.Memory), humanDisk(v.Disk), absoluteTime(v.Created), v.Image, v.Labels)
	if v.Template != "" {
		text += "Template: " + v.Template + "\n"
	}
	if v.Policy != "" {
		text += "Policy: " + v.Policy + "\n"
	}
	if len(v.GuestTCPPorts) > 0 {
		text += fmt.Sprintf("Guest TCP hints (ACL controls access): %v\n", v.GuestTCPPorts)
	}
	if v.LastOperation != nil {
		text += fmt.Sprintf("Last operation: %s %s\n", v.LastOperation.ID, v.LastOperation.State)
	}
	text += fmt.Sprintf("Node: %s\nNode state: %s\nKey expiry: %s\n", v.Node, v.NodeState, v.KeyExpiry)
	for _, diagnostic := range v.NodeDiagnostics {
		text += "Node diagnostic: " + diagnostic + "\n"
	}
	if v.ApprovalURL != "" {
		text += "Approve: " + v.ApprovalURL + "\n"
		if v.ApprovalExpires != nil {
			text += "Approval expires: " + v.ApprovalExpires.Format(time.RFC3339) + "\n"
		}
	}
	return text
}
func commandHelp(cmd string) (string, bool) {
	help := map[string]string{
		"reauth":   "reauth VM [--json] (stopped VM; requires vm.start and vm.stop)",
		"create":   "create NAME [IMAGE|--image OCI] [--template NAME] [--policy NAME] [--cpus N] [--memory SIZE] [--disk-size SIZE] [--provision-user NAME:UID:GID:HOME] [--userdata INLINE|-] [--label K=V]... [--owner tag:NAME] [--no-tailnet] [--no-start]",
		"template": "template ls|show NAME|create NAME|edit NAME|rm NAME|validate [--owner tag:NAME] [--json]; create/edit/validate read one YAML document from stdin",
		"policy":   "policy ls|show NAME|create NAME|edit NAME|rm NAME|validate [--owner tag:NAME] [--json]; create/edit/validate read HCL from stdin",
		"ls":       "ls [--json]", "show": "show VM [--json]", "start": "start VM [--json]", "stop": "stop VM [--force] [--timeout DURATION] [--json]", "restart": "restart VM [--json]", "rm": "rm VM [--force] [--yes|--json]", "set": "set VM name=NAME|cpus=N|memory=SIZE|disk=SIZE... [--json]", "shell": "shell VM [-u USER] (requires ssh -t)", "exec": "exec VM [-u USER] [-w DIR] [-e K=V]... [-t] -- CMD...", "logs": "logs VM [--follow] [--stream monitor|serial|exec|network|network-audit] [--output stdout|stderr]", "ops": "ops [show op_ULID] [--json]", "whoami": "whoami [--json]", "version": "version [--json]", "help": "help [COMMAND] [--json]",
	}
	value, ok := help[cmd]
	return value + "\n", ok
}
