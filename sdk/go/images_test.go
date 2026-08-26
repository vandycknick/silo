package silo

import "testing"

func TestImageHandleUsesStrongSizes(t *testing.T) {
	value, err := decodeImageHandle([]byte(`{"requested_reference":"a","selected_reference":"b","selected_manifest_digest":"c","config_digest":"d","image_id":"e","platform":{"os":"linux","architecture":"amd64"},"size_bytes":42,"created_at_unix_ms":1,"updated_at_unix_ms":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if value.Size == nil || value.Size.Bytes() != 42 {
		t.Fatalf("size = %#v", value.Size)
	}
}

func TestOCIConfigPreservesAbsentAndEmptyCollections(t *testing.T) {
	absent := imageDetailWire{}
	if absent.Config.Entrypoint != nil || absent.Config.Labels != nil {
		t.Fatal("zero-value OCI config should preserve absent collections")
	}
	emptyStrings := []string{}
	emptyLabels := map[string]string{}
	empty := OCIImageConfig{Entrypoint: &emptyStrings, Command: &emptyStrings, Env: &emptyStrings, Labels: &emptyLabels}
	if empty.Entrypoint == nil || len(*empty.Entrypoint) != 0 || empty.Labels == nil || len(*empty.Labels) != 0 {
		t.Fatal("OCI config did not preserve explicitly empty collections")
	}
}
