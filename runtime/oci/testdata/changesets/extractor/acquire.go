//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/containerd/containerd/v2/pkg/archive/compression"
)

type Pin struct {
	Name       string   `json:"name"`
	Builder    string   `json:"builder"`
	Registry   string   `json:"registry"`
	Repository string   `json:"repository"`
	Tag        string   `json:"tag"`
	Platform   string   `json:"platform"`
	Manifest   string   `json:"manifest"`
	Index      string   `json:"index"`
	Config     string   `json:"config"`
	Provenance []string `json:"provenance"`
}
type Corpus struct {
	Schema int   `json:"schema"`
	Images []Pin `json:"images"`
}
type Descriptor struct {
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	MediaType string `json:"mediaType"`
}
type Manifest struct {
	Config Descriptor   `json:"config"`
	Layers []Descriptor `json:"layers"`
}

type registry struct {
	client *http.Client
	tokens map[string]string
}

func (r *registry) get(ctx context.Context, pin Pin, category, ref string) (*http.Response, error) {
	location := "https://" + pin.Registry + "/v2/" + pin.Repository + "/" + category + "/" + ref
	tokenKey := pin.Registry + "/" + pin.Repository
	for attempt := range 2 {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json")
		if token := r.tokens[tokenKey]; token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := r.client.Do(request)
		if err != nil {
			return nil, err
		}
		if response.StatusCode == http.StatusOK {
			return response, nil
		}
		challenge := response.Header.Get("WWW-Authenticate")
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized || attempt != 0 {
			return nil, fmt.Errorf("GET %s: HTTP %d", location, response.StatusCode)
		}
		if !strings.HasPrefix(strings.ToLower(challenge), "bearer ") {
			return nil, fmt.Errorf("unsupported registry authentication %q", challenge)
		}
		attrs := make(map[string]string)
		expression, err := regexp.Compile(`([a-zA-Z]+)="([^"]*)"`)
		if err != nil {
			return nil, err
		}
		for _, match := range expression.FindAllStringSubmatch(challenge, -1) {
			attrs[match[1]] = match[2]
		}
		realm, err := url.Parse(attrs["realm"])
		if err != nil || realm.Scheme != "https" {
			return nil, fmt.Errorf("invalid HTTPS token realm")
		}
		query := realm.Query()
		for _, key := range []string{"service", "scope"} {
			if value := attrs[key]; value != "" {
				query.Set(key, value)
			}
		}
		realm.RawQuery = query.Encode()
		auth, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
		if err != nil {
			return nil, err
		}
		response, err = r.client.Do(auth)
		if err != nil {
			return nil, err
		}
		var token struct {
			Token       string `json:"token"`
			AccessToken string `json:"access_token"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&token)
		response.Body.Close()
		if response.StatusCode != http.StatusOK || decodeErr != nil {
			return nil, fmt.Errorf("token endpoint: HTTP %d, %v", response.StatusCode, decodeErr)
		}
		if token.Token == "" {
			token.Token = token.AccessToken
		}
		if token.Token == "" {
			return nil, fmt.Errorf("empty registry token")
		}
		r.tokens[tokenKey] = token.Token
	}
	return nil, fmt.Errorf("registry authentication exhausted")
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, ch := range value[7:] {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}
func (r *registry) object(ctx context.Context, pin Pin, category string, descriptor Descriptor, path string) error {
	if !validDigest(descriptor.Digest) || descriptor.Size < 0 || descriptor.Size > 1<<40 {
		return fmt.Errorf("invalid descriptor")
	}
	response, err := r.get(ctx, pin, category, descriptor.Digest)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	good := false
	defer func() {
		file.Close()
		if !good {
			os.Remove(path)
		}
	}()
	digest := sha256.New()
	count, err := io.Copy(io.MultiWriter(file, digest), io.LimitReader(response.Body, descriptor.Size+1))
	if err != nil {
		return err
	}
	if count != descriptor.Size {
		return fmt.Errorf("descriptor length expected %d got %d", descriptor.Size, count)
	}
	if actual := "sha256:" + hex.EncodeToString(digest.Sum(nil)); actual != descriptor.Digest {
		return fmt.Errorf("descriptor hash expected %s got %s", descriptor.Digest, actual)
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	good = true
	return nil
}
func (r *registry) manifest(ctx context.Context, pin Pin, path string) ([]byte, error) {
	response, err := r.get(ctx, pin, "manifests", pin.Manifest)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 4<<20 || sha(data) != pin.Manifest {
		return nil, fmt.Errorf("manifest size/digest mismatch")
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, err
	}
	return data, nil
}
func decodeBlob(blob, tar, diffID string) error {
	input, err := os.Open(blob)
	if err != nil {
		return err
	}
	defer input.Close()
	decoded, err := compression.DecompressStream(input)
	if err != nil {
		return err
	}
	defer decoded.Close()
	output, err := os.OpenFile(tar, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	good := false
	defer func() {
		output.Close()
		if !good {
			os.Remove(tar)
		}
	}()
	digest := sha256.New()
	count, err := io.Copy(io.MultiWriter(output, digest), io.LimitReader(decoded, (1<<40)+1))
	if err != nil {
		return err
	}
	if count > 1<<40 {
		return fmt.Errorf("decoded tar exceeds 1 TiB evidence bound")
	}
	if actual := "sha256:" + hex.EncodeToString(digest.Sum(nil)); actual != diffID {
		return fmt.Errorf("full decoded diff_id expected %s got %s", diffID, actual)
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	good = true
	return nil
}

func acquireCommand(args []string) error {
	flags := flag.NewFlagSet("acquire", flag.ContinueOnError)
	corpusPath := flags.String("corpus", "", "pinned corpus JSON")
	out := flags.String("out", "", "new acquisition directory")
	image := flags.String("image", "", "single corpus image name (required)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *corpusPath == "" || *out == "" || *image == "" {
		return fmt.Errorf("acquire requires --corpus --out --image")
	}
	var corpus Corpus
	if err := readJSON(*corpusPath, &corpus); err != nil {
		return err
	}
	if corpus.Schema != 1 {
		return fmt.Errorf("unsupported corpus schema")
	}
	var pin *Pin
	for index := range corpus.Images {
		if corpus.Images[index].Name == *image {
			pin = &corpus.Images[index]
			break
		}
	}
	if pin == nil {
		return fmt.Errorf("image %q absent from corpus", *image)
	}
	if pin.Platform != "linux/amd64" || !validDigest(pin.Manifest) || !validDigest(pin.Config) {
		return fmt.Errorf("invalid corpus pin")
	}
	if err := os.Mkdir(*out, 0700); err != nil {
		return fmt.Errorf("acquisition output must be new: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 290*time.Second)
	defer cancel()
	client := registry{client: &http.Client{Timeout: 280 * time.Second}, tokens: make(map[string]string)}
	if err := writeJSON(filepath.Join(*out, "pin.json"), pin); err != nil {
		return err
	}
	raw, err := client.manifest(ctx, *pin, filepath.Join(*out, "manifest.json"))
	if err != nil {
		return err
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	if manifest.Config.Digest != pin.Config {
		return fmt.Errorf("pinned config mismatch")
	}
	if err := client.object(ctx, *pin, "blobs", manifest.Config, filepath.Join(*out, "config.json")); err != nil {
		return err
	}
	var config struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		RootFS       struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if err := readJSON(filepath.Join(*out, "config.json"), &config); err != nil {
		return err
	}
	if config.OS != "linux" || config.Architecture != "amd64" || len(config.RootFS.DiffIDs) != len(manifest.Layers) || len(manifest.Layers) > 1024 {
		return fmt.Errorf("platform/layer-count mismatch")
	}
	item := Case{Name: pin.Name, Expected: make([]Row, 0), Layers: make([]Layer, 0), Provenance: pin}
	for index, descriptor := range manifest.Layers {
		blob := fmt.Sprintf("layer-%04d.blob", index)
		tar := fmt.Sprintf("layer-%04d.tar", index)
		if err := client.object(ctx, *pin, "blobs", descriptor, filepath.Join(*out, blob)); err != nil {
			return fmt.Errorf("layer %d acquisition: %w", index, err)
		}
		if err := decodeBlob(filepath.Join(*out, blob), filepath.Join(*out, tar), config.RootFS.DiffIDs[index]); err != nil {
			return fmt.Errorf("layer %d decode: %w", index, err)
		}
		item.Layers = append(item.Layers, Layer{Tar: tar, Blob: blob, Digest: descriptor.Digest, Size: descriptor.Size, MediaType: descriptor.MediaType, DiffID: config.RootFS.DiffIDs[index]})
	}
	return writeJSON(filepath.Join(*out, "acquired.json"), Request{Schema: 1, Cases: []Case{item}})
}
