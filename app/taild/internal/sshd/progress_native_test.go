package sshd

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOpenSSHSpinnerUsesActualImagePullAndClearsBeforePrompt(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	s, caller, registry := nativeService(t, "spinner", "user:7")
	entered, release := make(chan struct{}), make(chan struct{})
	var once, unblock sync.Once
	defer func() { unblock.Do(func() { close(release) }) }()
	registry.BeforeManifest = func() {
		once.Do(func() {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
			}
		})
	}
	address := terminalSSHServer(t, s, caller)
	c := openTerminalClient(t, address, "")
	c.wait(t, lobbyPrompt, 1)
	c.send(t, "create --name spinner-vm --no-start\r")
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("OCI pull not reached")
	}
	c.wait(t, "Pulling", 2)
	if !strings.Contains(c.text(), "\x1b[2K") {
		t.Fatal("missing redraw", c.text())
	}
	unblock.Do(func() { close(release) })
	c.wait(t, lobbyPrompt, 2)
	text := c.text()
	check := strings.LastIndex(text, "✓ Created")
	if check < 0 || !strings.Contains(text[check:], "ssh silo start spinner-vm") || strings.Contains(text[check:], "\r\x1b[2K") {
		t.Fatal("spinner survived completion", text)
	}
	c.send(t, "policy --help\r")
	c.wait(t, lobbyPrompt, 3)
	if !strings.Contains(c.text(), "Commands:\r\n") || strings.Contains(c.text(), "ls|show NAME") {
		t.Fatal(c.text())
	}
	c.send(t, "\x04")
	c.exit(t)
	for _, tty := range []bool{false, true} {
		out, diagnostic, code := sshPipeCommand(t, address, "create --no-start --json", nil, tty)
		if code != 0 || len(diagnostic) != 0 || !strings.Contains(string(out), `"completion":`) {
			t.Fatal("JSON progress leaked", code, string(out), string(diagnostic))
		}
	}
}
