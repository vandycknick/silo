// Package bootenv must depend only on os. Its github.com import path sorts
// before upstream environment readers once os is eligible for initialization.
package bootenv

import "os"

func init() {
	for _, entry := range os.Environ() {
		if !(len(entry) >= 3 && entry[:3] == "TS_") && !(len(entry) >= 6 && entry[:6] == "TSNET_") && !(len(entry) >= 9 && entry[:9] == "SILO_NET_") {
			continue
		}
		end := 0
		for end < len(entry) && entry[end] != '=' {
			end++
		}
		if err := os.Unsetenv(entry[:end]); err != nil {
			_, _ = os.Stderr.WriteString("taild: cannot isolate startup environment\n")
			os.Exit(1)
		}
	}
}
