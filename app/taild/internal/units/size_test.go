package units

import (
	"testing"
	"time"
)

func TestExactSizes(t *testing.T) {
	for _, v := range []struct {
		s string
		n uint64
	}{{"4GiB", 4 << 30}, {"32MiB", 32 << 20}, {"100GB", 100000000000}, {"0", 0}, {"17B", 17}} {
		n, e := Bytes(v.s)
		if e != nil || n != v.n {
			t.Fatalf("%s: %d %v", v.s, n, e)
		}
		var size Size
		if e := size.UnmarshalText([]byte(v.s)); e != nil || uint64(size) != v.n {
			t.Fatalf("%s: %d %v", v.s, size, e)
		}
	}
	for _, s := range []string{"", "-1", "1.5GiB", "8garbage", "18446744073709551615TiB", " 8GiB"} {
		if _, e := Bytes(s); e == nil {
			t.Fatal(s)
		}
	}
}

func TestSizeStringPicksLargestExactUnit(t *testing.T) {
	for _, v := range []struct {
		size Size
		want string
	}{{4 << 30, "4GiB"}, {4_000_000_000, "4GB"}, {256 << 20, "256MiB"}, {7 << 30, "7GiB"}, {1536 << 20, "1536MiB"}, {17, "17B"}, {0, "0B"}, {1000, "1KB"}} {
		if got := v.size.String(); got != v.want {
			t.Fatalf("%d: %q, want %q", uint64(v.size), got, v.want)
		}
	}
}

func TestDurationRequiresUnit(t *testing.T) {
	var d Duration
	if e := d.UnmarshalText([]byte("250ms")); e != nil || d.Duration != 250*time.Millisecond {
		t.Fatal(d, e)
	}
	for _, s := range []string{"", "4", "fast", "1.5"} {
		if e := d.UnmarshalText([]byte(s)); e == nil {
			t.Fatal(s)
		}
	}
}
