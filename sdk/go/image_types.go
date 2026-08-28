package silo

import "time"

type ImagePlatform struct {
	OS           string  `json:"os"`
	Architecture string  `json:"architecture"`
	Variant      *string `json:"variant"`
}
type ImageHandle struct {
	RequestedReference     string        `json:"requested_reference"`
	SelectedReference      string        `json:"selected_reference"`
	SelectedManifestDigest string        `json:"selected_manifest_digest"`
	ConfigDigest           string        `json:"config_digest"`
	ImageID                string        `json:"image_id"`
	Platform               ImagePlatform `json:"platform"`
	Size                   *ByteSize
	CreatedAt              time.Time
	UpdatedAt              time.Time
	LastUsedAt             *time.Time
}
type OCIImageConfig struct {
	Entrypoint *[]string          `json:"entrypoint"`
	Command    *[]string          `json:"command"`
	Env        *[]string          `json:"env"`
	WorkingDir *string            `json:"working_dir"`
	User       *string            `json:"user"`
	Labels     *map[string]string `json:"labels"`
	StopSignal *string            `json:"stop_signal"`
}
type ImageLayerDetail struct {
	BlobDigest       string `json:"blob_digest"`
	DiffID           string `json:"diff_id"`
	MediaType        string `json:"media_type"`
	CompressedSize   *ByteSize
	UncompressedSize *ByteSize
	Position         int64 `json:"position"`
}
type ImageDetail struct {
	Handle ImageHandle        `json:"handle"`
	Config OCIImageConfig     `json:"config"`
	Layers []ImageLayerDetail `json:"layers"`
}
type ImagePruneReport struct {
	ReferencesRemoved uint64 `json:"references_removed"`
	ArtifactsRemoved  uint64 `json:"artifacts_removed"`
	BytesRemoved      ByteSize
}
