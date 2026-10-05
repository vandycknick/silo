package commands

import (
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"

	"github.com/vandycknick/silo/app/taild/internal/jobs"
)

type progressDisplay struct {
	out      io.Writer
	animated bool
	width    int
	frame    int
	visible  bool
	message  string
}

func (p *progressDisplay) clear() error {
	if !p.visible {
		return nil
	}
	p.visible = false
	_, err := io.WriteString(p.out, "\r\x1b[2K")
	return err
}

func (p *progressDisplay) tick() error {
	if !p.animated {
		return nil
	}
	frames := []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
	text := []rune(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, fmt.Sprintf("   %c %s", frames[p.frame%len(frames)], p.message)))
	p.frame++
	width := p.width
	if width <= 0 {
		width = 80
	}
	if len(text) > max(1, width-1) {
		text = text[:max(1, width-1)]
	}
	p.visible = true
	_, err := fmt.Fprintf(p.out, "\r\x1b[2K%s", string(text))
	return err
}

func phase(line, target string) string {
	for _, entry := range []struct{ prefix, label string }{
		{"pulling ", "Pulling"}, {"creating ", "Creating"}, {"materializing ", "Creating"},
		{"starting ", "Starting"}, {"start ", "Starting"}, {"stopping ", "Stopping"}, {"stop ", "Stopping"},
		{"restart ", "Restarting"}, {"remove ", "Removing"}, {"set ", "Updating"},
		{"preparing ", "Preparing"},
	} {
		if rest, ok := strings.CutPrefix(line, entry.prefix); ok {
			if rest == "VM" || rest == "stopped VM" {
				rest = target
			}
			return fmt.Sprintf("%-12s %s", entry.label, rest)
		}
	}
	if strings.HasPrefix(line, "waiting for guest") {
		return fmt.Sprintf("%-12s %s", "Preparing", target)
	}
	if strings.HasPrefix(line, "checking Tailscale") {
		return fmt.Sprintf("%-12s onboarding link", "Tailscale")
	}
	if line == "guest ready" {
		return fmt.Sprintf("%-12s %s", "Ready", target)
	}
	if strings.HasPrefix(line, "approve: ") {
		return "Waiting for Tailscale approval"
	}
	return line
}

func completionText(op jobs.Operation, lobby string) string {
	label := map[string]string{"create": "Created", "start": "Started", "restart": "Restarted", "stop": "Stopped", "remove": "Removed", "set": "Updated"}[op.Kind]
	if label == "" {
		label = "Completed"
	}
	name := op.VM
	if op.Completion != nil {
		name = op.Completion.Name
		if op.Kind == "create" && op.Completion.Running {
			label = "Ready"
		}
	}
	elapsed := time.Duration(0)
	if op.Finished != nil {
		elapsed = max(0, op.Finished.Sub(op.Started))
	}
	text := fmt.Sprintf("   ✓ %-12s %s (%.1fs)\n", label, name, elapsed.Seconds())
	v := op.Completion
	if v == nil || op.Kind != "create" && op.Kind != "start" && op.Kind != "restart" {
		return text
	}
	if lobby == "" {
		lobby = "silo"
	}
	if !v.Running {
		return text + fmt.Sprintf("\nStart\n  ssh %s start %s\n", lobby, name)
	}
	text += fmt.Sprintf("\nShell\n  ssh -t %s shell %s\n", lobby, name)
	if v.Node != "" && v.NodeState == "enrolled" {
		text += fmt.Sprintf("\nSSH\n  ssh %s@%s\n", v.User, v.Node)
	} else if v.ApprovalURL != "" {
		text += "\nTailscale · approval required\n  " + v.ApprovalURL + "\n"
	} else if v.NodeState != "none" && v.NodeState != "" {
		text += fmt.Sprintf("\nTailscale · %s\n  Check with: show %s\n", v.NodeState, name)
	}
	return text
}
