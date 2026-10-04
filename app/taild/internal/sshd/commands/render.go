package commands

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/service"
)

func renderList(vms []service.VM) string {
	return renderListAt(vms, time.Now())
}

func renderListAt(vms []service.VM, now time.Time) string {
	var b strings.Builder
	table := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(table, "NAME\tSTATE\tNODE\tCPUS\tMEMORY\tCREATED")
	for _, vm := range vms {
		node := vm.Node
		if node == "" {
			node = string(vm.NodeState)
		}
		_, _ = fmt.Fprintf(table, "%s\t%s\t%s\t%d\t%s\t%s\n", vm.Name, vm.State, node, vm.CPUs, humanMemory(vm.Memory), relativeTime(vm.Created, now))
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

func renderVersion(v service.Version) string {
	return fmt.Sprintf("taild %s · SDK %s · runtime %s · tailscale %s\n", v.Taild, v.SDK, v.Runtime, v.Tailscale)
}

func renderWhoAmI(who service.WhoAmI) string {
	p := who.Peer
	user := p.Login
	for _, principal := range p.Principals {
		if principal.IsTag() {
			user = "tagged device"
			break
		}
	}
	if user == "" {
		user = "unknown"
	}
	return fmt.Sprintf("User: %s\nNode: %s\n", user, strings.TrimSuffix(p.NodeName, "."))
}

func renderOps(ops []jobs.Operation) string {
	var b strings.Builder
	for _, op := range ops {
		fmt.Fprintf(&b, "%s %s %s %s\n", op.ID, op.Kind, op.VM, op.State)
	}
	return b.String()
}

// renderDocuments prints show verbatim; every other verb lists summaries.
func renderDocuments(verb string, docs []service.Document) string {
	if verb == "show" {
		return docs[0].Content
	}
	var b strings.Builder
	for _, d := range docs {
		fmt.Fprintf(&b, "%s %s %s\n", d.Kind, d.Name, d.Tier)
		if t := d.Template; t != nil {
			optional(&b, "Description", t.Description)
			optional(&b, "Image", t.Image)
			if t.Resources != nil {
				optional(&b, "CPUs", t.Resources.CPUs)
				optional(&b, "Memory", t.Resources.Memory)
			}
			optional(&b, "Disk", t.DiskSize)
			if t.Network != nil {
				optional(&b, "Policy", t.Network.PolicyRef)
				if len(t.Network.Publish) > 0 {
					fmt.Fprintf(&b, "Guest TCP hints (ACL controls access): %v\n", t.Network.Publish)
				}
			}
		}
		if d.Secrets != nil {
			for _, slot := range d.Secrets.Slots {
				fmt.Fprintf(&b, "Secret: %s (key %s, required %t)\n", slot.Name, slot.Source.Key, slot.Required)
			}
		}
	}
	return b.String()
}

func optional[T any](b *strings.Builder, label string, v *T) {
	if v != nil {
		fmt.Fprintf(b, "%s: %v\n", label, *v)
	}
}
