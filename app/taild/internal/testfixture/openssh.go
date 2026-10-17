package testfixture

import (
	"net"
	"os/exec"
	"testing"
)

// OpenSSH is the client invocation for a session against a test SSH server
// that ignores authentication, with a PTY when tty is set. It skips the test
// when no OpenSSH client is installed.
func OpenSSH(t *testing.T, address string, tty bool, command string) (string, []string) {
	t.Helper()
	path, e := exec.LookPath("ssh")
	if e != nil {
		Unavailable(t, "OpenSSH ssh is required")
	}
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		t.Fatal(e)
	}
	mode := "-T"
	if tty {
		mode = "-tt"
	}
	args := []string{"-F", "/dev/null", mode, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "PreferredAuthentications=none", "-o", "ConnectTimeout=5", "-p", port, "domain-test@" + host}
	if command != "" {
		args = append(args, command)
	}
	return path, args
}
