// Package units holds the exact size and duration types the configuration and
// capability grants are written in.
package units

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
)

// Size is an exact byte count that reads and prints with a unit suffix.
type Size uint64

// Largest scale first, so printing picks the biggest unit that divides exactly.
var suffixes = []struct {
	name  string
	scale uint64
}{{"TiB", 1 << 40}, {"TB", 1000000000000}, {"GiB", 1 << 30}, {"GB", 1000000000}, {"MiB", 1 << 20}, {"MB", 1000000}, {"KiB", 1 << 10}, {"KB", 1000}, {"B", 1}}

// Bytes accepts exact nonnegative integer sizes, never floating-point quotas.
func Bytes(s string) (uint64, error) {
	scale := uint64(1)
	for _, v := range suffixes {
		if strings.HasSuffix(s, v.name) {
			s = strings.TrimSuffix(s, v.name)
			scale = v.scale
			break
		}
	}
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return 0, errors.New("invalid integer byte size")
	}
	n, e := strconv.ParseUint(s, 10, 64)
	if e != nil || n > math.MaxUint64/scale {
		return 0, errors.New("byte size overflow")
	}
	return n * scale, nil
}

func (s *Size) UnmarshalText(text []byte) error {
	n, e := Bytes(string(text))
	*s = Size(n)
	return e
}

// String renders the size in the largest unit that divides it exactly.
func (s Size) String() string {
	for _, v := range suffixes {
		if s != 0 && uint64(s)%v.scale == 0 {
			return strconv.FormatUint(uint64(s)/v.scale, 10) + v.name
		}
	}
	return strconv.FormatUint(uint64(s), 10) + "B"
}

// Duration is a time.Duration that must be written with a unit, so a bare
// number in a configuration file is a mistake rather than nanoseconds.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalText(text []byte) error {
	v, e := time.ParseDuration(string(text))
	if e != nil {
		return errors.New("invalid duration")
	}
	d.Duration = v
	return nil
}
