package commands

import (
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

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
		if vm.ApprovalURL != "" {
			fmt.Fprintf(&b, "Approve %s: %s", vm.Name, vm.ApprovalURL)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func renderShow(v service.VM) string {
	owner := string(v.Owner)
	if !v.Owner.IsTag() && v.OwnerLogin != "" {
		owner = v.OwnerLogin
	}
	user := v.DefaultUser
	if user == "" {
		user = "root"
	}
	text := fmt.Sprintf("Name: %s\nID: %s\nOwner: %s\nGuest user: %s\nState: %s\nCPUs: %d\nMemory: %s\nDisk: %s\nCreated: %s\nImage: %s\n", safeText(v.Name), safeText(v.ID), safeText(owner), safeText(user), v.State, v.CPUs, humanMemory(v.Memory), humanDisk(v.Disk), absoluteTime(v.Created), safeText(v.Image))
	if len(v.Labels) > 0 {
		text += "Labels:\n"
		keys := make([]string, 0, len(v.Labels))
		for key := range v.Labels {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			text += fmt.Sprintf("  %s: %s\n", safeText(key), safeText(v.Labels[key]))
		}
	}
	if v.Template != "" {
		text += "Template: " + safeText(v.Template) + "\n"
	}
	if len(v.Tags) > 0 {
		text += "Tags: " + safeText(strings.Join(v.Tags, ", ")) + "\n"
	}
	if v.Policy != "" {
		text += "Policy: " + safeText(v.Policy) + "\n"
	}
	if len(v.GuestTCPPorts) > 0 {
		text += fmt.Sprintf("Guest TCP hints (ACL controls access): %v\n", v.GuestTCPPorts)
	}
	text += fmt.Sprintf("Node: %s\nNode state: %s\nKey expiry: %s\n", safeText(v.Node), safeText(string(v.NodeState)), expiryText(v, time.Now()))
	for _, diagnostic := range v.NodeDiagnostics {
		text += "Node diagnostic: " + safeText(diagnostic) + "\n"
	}
	if v.ApprovalURL != "" {
		text += "Login: " + safeText(v.ApprovalURL) + "\n"
	}
	return text
}

func safeText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return '�'
		}
		return r
	}, s)
}

func expiryText(v service.VM, now time.Time) string {
	text := "Unavailable"
	if v.KeyExpiry == "never" {
		text = "Never"
	} else if expiry, err := time.Parse(time.RFC3339, v.KeyExpiry); err == nil && !expiry.IsZero() {
		text = absoluteTime(expiry)
		if !expiry.After(now) {
			text += " (expired)"
		}
	}
	if text != "Unavailable" && v.KeyExpiryLastKnown {
		text += " (last known)"
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
