package silo

import (
	"math"
	"testing"
)

func TestByteSizeConstructors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		size ByteSize
		want uint64
	}{
		{name: "bytes", size: Bytes(7), want: 7},
		{name: "kilobytes", size: Kilobytes(2), want: 2_000},
		{name: "kibibytes", size: Kibibytes(2), want: 2_048},
		{name: "megabytes", size: Megabytes(2), want: 2_000_000},
		{name: "mebibytes", size: Mebibytes(2), want: 2_097_152},
		{name: "gigabytes", size: Gigabytes(2), want: 2_000_000_000},
		{name: "gibibytes", size: Gibibytes(2), want: 2_147_483_648},
		{name: "zero value", size: ByteSize{}, want: 0},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := test.size.Bytes(); got != test.want {
				t.Fatalf("Bytes() = %d, want %d", got, test.want)
			}
			if err := test.size.validate("size"); err != nil {
				t.Fatalf("validate() failed: %v", err)
			}
		})
	}
}

func TestByteSizeRejectsOverflow(t *testing.T) {
	t.Parallel()

	size := Gibibytes(math.MaxUint64)
	if got := size.Bytes(); got != 0 {
		t.Fatalf("overflowed Bytes() = %d, want 0", got)
	}
	if err := size.validate("memory"); !IsErrorKind(err, ErrorInvalidArgument) {
		t.Fatalf("validate() error = %v, want ErrorInvalidArgument", err)
	}
}
