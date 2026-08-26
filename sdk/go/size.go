package silo

import (
	"fmt"
	"math"
)

// ByteSize is an exact number of bytes used for memory and storage sizes.
// Its zero value represents zero bytes.
type ByteSize struct {
	bytes    uint64
	overflow bool
}

// Bytes constructs an exact byte size.
func Bytes(value uint64) ByteSize { return ByteSize{bytes: value} }

// Kilobytes constructs a decimal kilobyte size.
func Kilobytes(value uint64) ByteSize { return multipliedSize(value, 1_000) }

// Kibibytes constructs a binary kibibyte size.
func Kibibytes(value uint64) ByteSize { return multipliedSize(value, 1_024) }

// Megabytes constructs a decimal megabyte size.
func Megabytes(value uint64) ByteSize { return multipliedSize(value, 1_000_000) }

// Mebibytes constructs a binary mebibyte size.
func Mebibytes(value uint64) ByteSize { return multipliedSize(value, 1_048_576) }

// Gigabytes constructs a decimal gigabyte size.
func Gigabytes(value uint64) ByteSize { return multipliedSize(value, 1_000_000_000) }

// Gibibytes constructs a binary gibibyte size.
func Gibibytes(value uint64) ByteSize { return multipliedSize(value, 1_073_741_824) }

func multipliedSize(value, multiplier uint64) ByteSize {
	if value != 0 && multiplier > math.MaxUint64/value {
		return ByteSize{overflow: true}
	}
	return ByteSize{bytes: value * multiplier}
}

// Bytes returns the exact byte count. It returns zero for an overflowed constructor value;
// operations accepting ByteSize reject such values.
func (s ByteSize) Bytes() uint64 {
	if s.overflow {
		return 0
	}
	return s.bytes
}

// String formats the value as an exact byte count.
func (s ByteSize) String() string {
	if s.overflow {
		return "invalid byte size"
	}
	return fmt.Sprintf("%d B", s.bytes)
}

func (s ByteSize) validate(name string) error {
	if s.overflow {
		return newError(ErrorInvalidArgument, "", name+" overflows uint64 bytes")
	}
	return nil
}
