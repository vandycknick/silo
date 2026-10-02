package service

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"time"

	silo "github.com/vandycknick/silo/sdk/go"
)

type guestAccount struct{ name, home, shell string }

// Spawn resolves credentials but deliberately clears ambient environment. Read
// the selected account from the guest, rather than borrowing daemon identity or
// a different provisioned account's HOME and shell.
func guestIdentity(ctx context.Context, m *silo.Machine, selector string, stored *silo.GuestUser) (guestAccount, error) {
	// Account lookup enriches the environment, not execution admission. Images
	// without a POSIX shell can still execute binaries. Keep the selector intact
	// so the agent remains authoritative for credentials and unknown accounts.
	fallback := guestAccount{shell: "/bin/sh"}
	name, _, _ := strings.Cut(selector, ":")
	uid, numericErr := strconv.ParseUint(name, 10, 32)
	if name == "root" || numericErr == nil && uid == 0 {
		fallback = guestAccount{name: "root", home: "/root", shell: "/bin/sh"}
	} else if stored != nil && (name == stored.Name || numericErr == nil && uid == uint64(stored.UID)) {
		fallback = guestAccount{name: stored.Name, home: stored.Home, shell: "/bin/bash"}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// The guard also rejects the rescue shell's partial read implementation,
	// which does not report EOF. All reader operations are shell builtins.
	const reader = `command -v read && command -v printf || exit 125
while IFS= read -r line || [ -n "$line" ]; do printf '%s\n' "$line"; done < /etc/passwd`
	process, err := m.Spawn(ctx, "/bin/sh", []string{"-c", reader}, silo.WithExecUser("0:0"), silo.WithExecTimeout(5*time.Second))
	if err != nil {
		return guestAccount{}, err
	}
	defer func() { _ = process.Cancel(); _ = process.Close() }()
	var out bytes.Buffer
	for {
		event, err := process.Recv(ctx)
		if err != nil {
			return guestAccount{}, err
		}
		if event.Kind == silo.ExecutionEventStdout {
			if out.Len()+len(event.Data) > 1<<20 {
				return guestAccount{}, failure("operation_failed", "guest account database exceeds 1MiB", 7)
			}
			out.Write(event.Data)
		}
		if event.Kind == silo.ExecutionEventTerminal {
			if event.Result != nil {
				if event.Result.LaunchFailure != nil && event.Result.LaunchFailure.Reason == silo.LaunchFailureCommandNotFound {
					return fallback, nil
				}
				if event.Result.Kind == silo.ExecutionResultExited && event.Result.Code != nil && (*event.Result.Code == 125 || *event.Result.Code == 127) {
					return fallback, nil
				}
			}
			if event.Result == nil || event.Result.Kind != silo.ExecutionResultExited || event.Result.Code == nil || *event.Result.Code != 0 {
				return guestAccount{}, failure("operation_failed", "unable to read guest account database", 7)
			}
			break
		}
	}
	for _, line := range strings.Split(out.String(), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			continue
		}
		entryUID, err := strconv.ParseUint(fields[2], 10, 32)
		if fields[0] != name && !(numericErr == nil && err == nil && entryUID == uid) {
			continue
		}
		home, shell := fields[5], fields[6]
		if home == "" {
			home = "/"
		}
		if shell == "" {
			shell = "/bin/sh"
		}
		return guestAccount{name: fields[0], home: home, shell: shell}, nil
	}
	return guestAccount{shell: "/bin/sh"}, nil
}
