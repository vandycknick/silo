// Package bootenv isolates ambient credentials and knobs before upstream init.
// Keep this package dependent ONLY on os. Go initializes the first eligible
// package in import-path order: this github.com/... path precedes tailscale.com,
// and is eligible as soon as os is initialized, before upstream environment
// readers and envknob registration. See README.md and actual init-trace tests.
package bootenv

import "os"

func init() {
	if err := Clear(); err != nil {
		// No environment names or values may be printed on this failure path.
		_, _ = os.Stderr.WriteString("netd: cannot isolate startup environment\n")
		os.Exit(1)
	}
}

func Isolated(name string) bool {
	return (len(name) >= 9 && name[:9] == "SILO_NET_") || (len(name) >= 3 && name[:3] == "TS_") || (len(name) >= 6 && name[:6] == "TSNET_")
}

func Clear() error {
	for _, entry := range os.Environ() {
		if !Isolated(entry) {
			continue
		}
		end := 0
		for end < len(entry) && entry[end] != '=' {
			end++
		}
		if err := os.Unsetenv(entry[:end]); err != nil {
			return err
		}
	}
	return nil
}
