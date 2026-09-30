package units

import "testing"

func TestExactSizes(t *testing.T) {
	for _, v := range []struct {
		s string
		n uint64
	}{{"4GiB", 4 << 30}, {"32MiB", 32 << 20}, {"100GB", 100000000000}, {"0", 0}, {"17B", 17}} {
		n, e := Bytes(v.s)
		if e != nil || n != v.n {
			t.Fatalf("%s: %d %v", v.s, n, e)
		}
	}
	for _, s := range []string{"", "-1", "1.5GiB", "8garbage", "18446744073709551615TiB", " 8GiB"} {
		if _, e := Bytes(s); e == nil {
			t.Fatal(s)
		}
	}
}
