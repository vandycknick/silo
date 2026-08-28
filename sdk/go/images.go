package silo

import (
	"context"
	"encoding/json"
	"time"
)

type ImagePullPolicy string

const (
	ImagePullIfMissing ImagePullPolicy = "if_missing"
	ImagePullAlways    ImagePullPolicy = "always"
	ImagePullNever     ImagePullPolicy = "never"
)

type imagePullConfig struct{ policy ImagePullPolicy }
type ImagePullOption func(*imagePullConfig)

func WithImagePullPolicy(policy ImagePullPolicy) ImagePullOption {
	return func(c *imagePullConfig) { c.policy = policy }
}

type imageRemoveConfig struct{ force bool }
type ImageRemoveOption func(*imageRemoveConfig)

func ForceImageRemoval() ImageRemoveOption { return func(c *imageRemoveConfig) { c.force = true } }

type imageRequest struct {
	Operation string          `json:"operation"`
	Reference string          `json:"reference,omitempty"`
	Policy    ImagePullPolicy `json:"policy,omitempty"`
	Force     bool            `json:"force,omitempty"`
}

// Images provides runtime-scoped OCI image cache operations.
type Images struct{ runtime *Runtime }

func (r *Runtime) Images() *Images { return &Images{runtime: r} }
func (i *Images) call(ctx context.Context, request imageRequest) ([]byte, error) {
	if i == nil || i.runtime == nil {
		return nil, newError(ErrorClosed, "", "image namespace is closed")
	}
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	i.runtime.mutex.RLock()
	defer i.runtime.mutex.RUnlock()
	if i.runtime.closed {
		return nil, newError(ErrorClosed, "", "runtime is closed")
	}
	data, err = i.runtime.native.ImageCall(data)
	if err != nil {
		return nil, fromNativeError(err)
	}
	return data, nil
}
func (i *Images) Pull(ctx context.Context, reference string, opts ...ImagePullOption) (*ImageHandle, error) {
	if reference == "" {
		return nil, newError(ErrorInvalidArgument, "", "image reference must not be empty")
	}
	config := imagePullConfig{}
	for _, option := range opts {
		if option == nil {
			return nil, newError(ErrorInvalidArgument, "", "image pull option must not be nil")
		}
		option(&config)
	}
	data, err := i.call(ctx, imageRequest{Operation: "pull", Reference: reference, Policy: config.policy})
	if err != nil {
		return nil, err
	}
	return decodeImageHandle(data)
}
func (i *Images) Lookup(ctx context.Context, reference string) (*ImageHandle, error) {
	if reference == "" {
		return nil, newError(ErrorInvalidArgument, "", "image reference must not be empty")
	}
	data, err := i.call(ctx, imageRequest{Operation: "get", Reference: reference})
	if err != nil {
		return nil, err
	}
	if string(data) == "null" {
		return nil, nil
	}
	return decodeImageHandle(data)
}
func (i *Images) List(ctx context.Context) ([]ImageHandle, error) {
	data, err := i.call(ctx, imageRequest{Operation: "list"})
	if err != nil {
		return nil, err
	}
	var wires []imageHandleWire
	if err = json.Unmarshal(data, &wires); err != nil {
		return nil, err
	}
	values := make([]ImageHandle, len(wires))
	for index := range wires {
		values[index] = wires[index].value()
	}
	return values, nil
}
func (i *Images) Inspect(ctx context.Context, reference string) (*ImageDetail, error) {
	if reference == "" {
		return nil, newError(ErrorInvalidArgument, "", "image reference must not be empty")
	}
	data, err := i.call(ctx, imageRequest{Operation: "inspect", Reference: reference})
	if err != nil {
		return nil, err
	}
	if string(data) == "null" {
		return nil, nil
	}
	var wire imageDetailWire
	if err = json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	return wire.value(), nil
}
func (i *Images) Remove(ctx context.Context, reference string, opts ...ImageRemoveOption) error {
	if reference == "" {
		return newError(ErrorInvalidArgument, "", "image reference must not be empty")
	}
	config := imageRemoveConfig{}
	for _, option := range opts {
		if option == nil {
			return newError(ErrorInvalidArgument, "", "image remove option must not be nil")
		}
		option(&config)
	}
	_, err := i.call(ctx, imageRequest{Operation: "remove", Reference: reference, Force: config.force})
	return err
}
func (i *Images) Prune(ctx context.Context) (*ImagePruneReport, error) {
	data, err := i.call(ctx, imageRequest{Operation: "prune"})
	if err != nil {
		return nil, err
	}
	var wire struct {
		References uint64 `json:"references_removed"`
		Artifacts  uint64 `json:"artifacts_removed"`
		Bytes      uint64 `json:"bytes_removed"`
	}
	if err = json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	return &ImagePruneReport{ReferencesRemoved: wire.References, ArtifactsRemoved: wire.Artifacts, BytesRemoved: Bytes(wire.Bytes)}, nil
}

type imageHandleWire struct {
	RequestedReference     string        `json:"requested_reference"`
	SelectedReference      string        `json:"selected_reference"`
	SelectedManifestDigest string        `json:"selected_manifest_digest"`
	ConfigDigest           string        `json:"config_digest"`
	ImageID                string        `json:"image_id"`
	Platform               ImagePlatform `json:"platform"`
	Size                   *uint64       `json:"size_bytes"`
	Created                int64         `json:"created_at_unix_ms"`
	Updated                int64         `json:"updated_at_unix_ms"`
	LastUsed               *int64        `json:"last_used_at_unix_ms"`
}

func (w imageHandleWire) value() ImageHandle {
	value := ImageHandle{RequestedReference: w.RequestedReference, SelectedReference: w.SelectedReference, SelectedManifestDigest: w.SelectedManifestDigest, ConfigDigest: w.ConfigDigest, ImageID: w.ImageID, Platform: w.Platform, CreatedAt: time.UnixMilli(w.Created), UpdatedAt: time.UnixMilli(w.Updated)}
	if w.Size != nil {
		s := Bytes(*w.Size)
		value.Size = &s
	}
	if w.LastUsed != nil {
		t := time.UnixMilli(*w.LastUsed)
		value.LastUsedAt = &t
	}
	return value
}
func decodeImageHandle(data []byte) (*ImageHandle, error) {
	var wire imageHandleWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	value := wire.value()
	return &value, nil
}

type layerWire struct {
	BlobDigest   string  `json:"blob_digest"`
	DiffID       string  `json:"diff_id"`
	MediaType    string  `json:"media_type"`
	Compressed   *uint64 `json:"compressed_size_bytes"`
	Uncompressed *uint64 `json:"uncompressed_size_bytes"`
	Position     int64   `json:"position"`
}
type imageDetailWire struct {
	Handle imageHandleWire `json:"handle"`
	Config OCIImageConfig  `json:"config"`
	Layers []layerWire     `json:"layers"`
}

func (w imageDetailWire) value() *ImageDetail {
	value := &ImageDetail{Handle: w.Handle.value(), Config: w.Config, Layers: make([]ImageLayerDetail, len(w.Layers))}
	for index, layer := range w.Layers {
		value.Layers[index] = ImageLayerDetail{BlobDigest: layer.BlobDigest, DiffID: layer.DiffID, MediaType: layer.MediaType, Position: layer.Position}
		if layer.Compressed != nil {
			s := Bytes(*layer.Compressed)
			value.Layers[index].CompressedSize = &s
		}
		if layer.Uncompressed != nil {
			s := Bytes(*layer.Uncompressed)
			value.Layers[index].UncompressedSize = &s
		}
	}
	return value
}
