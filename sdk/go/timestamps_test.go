package silo

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMachineTimestampDecoderPreservesMilliseconds(t *testing.T) {
	const ms int64 = 1790944496123 // 2026-10-02 12:34:56.123 UTC
	wire := []byte(`{"created_at_unix_ms":1790944496123,"modified_at_unix_ms":1790944496124,"updated_at_unix_ms":1790944496125,"started_at_unix_ms":1790944496126,"rootfs":{"created_at_unix_ms":1790944496127},"provision_report":{"started_at_unix_ms":1790944496128,"finished_at_unix_ms":1790944496789,"duration_ms":661}}`)
	data, err := decodeMachineData(wire)
	if err != nil {
		t.Fatal(err)
	}
	if data.CreatedAt.UTC().Format(time.RFC3339Nano) != "2026-10-02T12:34:56.123Z" {
		t.Fatal(data.CreatedAt)
	}
	for i, value := range []time.Time{data.CreatedAt, data.ModifiedAt, data.UpdatedAt, *data.StartedAt, data.RootFS.CreatedAt, data.ProvisionReport.StartedAt} {
		if value.UnixMilli() != ms+int64(i) {
			t.Fatal(i, value)
		}
	}
	if data.ProvisionReport.FinishedAt.UnixMilli() != 1790944496789 || data.ProvisionReport.Duration != 661*time.Millisecond {
		t.Fatal(data.ProvisionReport)
	}
	absent, err := decodeMachineData([]byte(`{}`))
	if err != nil || absent.StartedAt != nil || absent.RootFS != nil || absent.ProvisionReport != nil {
		t.Fatal(absent, err)
	}
}

func TestImageTimestampDecoderPreservesMilliseconds(t *testing.T) {
	wire := []byte(`{"created_at_unix_ms":1790944496123,"updated_at_unix_ms":1790944496456,"last_used_at_unix_ms":1790944496789}`)
	image, err := decodeImageHandle(wire)
	if err != nil {
		t.Fatal(err)
	}
	if image.CreatedAt.UTC().Format(time.RFC3339Nano) != "2026-10-02T12:34:56.123Z" || image.UpdatedAt.UnixMilli() != 1790944496456 || image.LastUsedAt == nil || image.LastUsedAt.UnixMilli() != 1790944496789 {
		t.Fatal(image)
	}
	var detail imageDetailWire
	if err := json.Unmarshal(append(append([]byte(`{"handle":`), wire...), '}'), &detail); err != nil {
		t.Fatal(err)
	}
	if !detail.value().Handle.CreatedAt.Equal(image.CreatedAt) {
		t.Fatal(detail)
	}
	absent, err := decodeImageHandle([]byte(`{}`))
	if err != nil || absent.LastUsedAt != nil {
		t.Fatal(absent, err)
	}
	zero, err := decodeImageHandle([]byte(`{"last_used_at_unix_ms":0}`))
	if err != nil || zero.LastUsedAt == nil || zero.LastUsedAt.UnixMilli() != 0 {
		t.Fatal(zero, err)
	}
}
