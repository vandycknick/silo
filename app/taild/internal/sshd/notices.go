package sshd

import (
	"context"
	"fmt"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/service"
)

// Poll only while the lobby owns the prompt. Join before dispatching a command,
// so notifications cannot race with JSON, confirmation or guest streams.
type lobbyNotices struct{ seen map[string]string }

func (n *lobbyNotices) prompt(ctx context.Context, s *service.Service, c service.Caller, streams service.IO) (string, error) {
	editor, ok := streams.Stdin.(*terminalInput)
	if !ok || s.Runtime == nil || !c.Peer.Permissions.Has(identity.Read) {
		return streams.Prompt(ctx, "silo> ", 16384)
	}
	watch, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-watch.Done():
				return
			case <-ticker.C:
			}
			call, stop := context.WithTimeout(watch, 5*time.Second)
			peer, err := c.Fresh(call)
			if err != nil {
				stop()
				return
			}
			vms, err := s.List(call, peer)
			stop()
			if err != nil {
				continue
			}
			present := map[string]bool{}
			for _, vm := range vms {
				present[vm.ID] = true
				if vm.ApprovalURL == "" {
					delete(n.seen, vm.ID)
					continue
				}
				if n.seen[vm.ID] == vm.ApprovalURL {
					continue
				}
				text := fmt.Sprintf("Tailscale login required for %s\n  %s\nUse: show %s\n", vm.Name, vm.ApprovalURL, vm.Name)
				if editor.notice(text) {
					n.seen[vm.ID] = vm.ApprovalURL
				}
			}
			for id := range n.seen {
				if !present[id] {
					delete(n.seen, id)
				}
			}
		}
	}()
	line, err := streams.Prompt(ctx, "silo> ", 16384)
	cancel()
	<-done
	return line, err
}

func (t *terminalInput) notice(text string) bool {
	t.sizeMu.Lock()
	defer t.sizeMu.Unlock()
	if !t.editing {
		return false
	}
	_, err := t.terminal.Write([]byte(text))
	return err == nil
}
