package service

import (
	"bytes"
	"io"
	"testing"
)

func TestTransferReaderLimit(t *testing.T) {
	for _, size := range []int{0, 4, 5} {
		reader := &transferReader{source: io.LimitReader(bytes.NewReader(bytes.Repeat([]byte{1}, size)), 5), remaining: 4}
		var output bytes.Buffer
		_, err := io.CopyBuffer(&output, reader, make([]byte, 2))
		if size <= 4 {
			if err != nil || reader.exceeded || output.Len() != size {
				t.Fatal(size, output.Len(), err)
			}
		} else if err == nil || !reader.exceeded || Categorize(err).Exit != 6 {
			t.Fatal(size, err)
		}
	}
}
