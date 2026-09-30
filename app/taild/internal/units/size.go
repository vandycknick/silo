package units

import (
	"errors"
	"math"
	"strconv"
	"strings"
)

// Bytes accepts exact nonnegative integer sizes, never floating-point quotas.
func Bytes(s string) (uint64, error) {
	suffixes := []struct {
		name  string
		scale uint64
	}{{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"TB", 1000000000000}, {"GB", 1000000000}, {"MB", 1000000}, {"KB", 1000}, {"B", 1}}
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
