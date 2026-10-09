// Package bootenv must depend only on the standard library. Its github.com
// import path sorts before upstream environment readers once those packages
// are eligible for initialization.
package bootenv

import (
	"os"
	"strings"
)

func init() {
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "TS_") && !strings.HasPrefix(entry, "TSNET_") && !strings.HasPrefix(entry, "SILO_NET_") {
			continue
		}
		name, _, _ := strings.Cut(entry, "=")
		if err := os.Unsetenv(name); err != nil {
			_, _ = os.Stderr.WriteString("taild: cannot isolate startup environment\n")
			os.Exit(1)
		}
	}
}
