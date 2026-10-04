package cmdline

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// ValueError carries a reason Parse may show to the peer. Any other parser
// error is reported without detail, so stray input never echoes back.
type ValueError struct{ Reason string }

func (e *ValueError) Error() string { return e.Reason }

// NonEmpty stores a value that must not be the empty string.
func NonEmpty(dst *string) func(string) error {
	return func(v string) error {
		if v == "" {
			return errors.New("empty value")
		}
		*dst = v
		return nil
	}
}

// Count stores a positive integer that fits a byte, as CPU counts do.
func Count(dst *uint64) func(string) error {
	return func(v string) error {
		n, e := strconv.ParseUint(v, 10, 64)
		if e != nil || n == 0 || n > 255 {
			return &ValueError{"expected a positive integer (1..255)"}
		}
		*dst = n
		return nil
	}
}

func Duration(dst *time.Duration) func(string) error {
	return func(v string) (e error) { *dst, e = time.ParseDuration(v); return e }
}

// KeyValue stores K=V pairs into a map; a repeated key keeps the last value.
func KeyValue(dst map[string]string) func(string) error {
	return func(v string) error {
		k, value, ok := strings.Cut(v, "=")
		if !ok {
			return errors.New("expected KEY=VALUE")
		}
		dst[k] = value
		return nil
	}
}
