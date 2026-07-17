package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

type npmRepository struct{}

func (npmRepository) ecosystem() Ecosystem {
	return EcosystemNPM
}

func (npmRepository) hosts() []string {
	return []string{"registry.npmjs.org", "registry.yarnpkg.com", "registry.npmjs.com"}
}

func (npmRepository) normalizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func (r npmRepository) classify(method string, _ string, requestPath string) Request {
	operation := requestOperation(method)
	if decoded, err := url.PathUnescape(requestPath); err == nil {
		requestPath = decoded
	}
	return r.classifyOperation(requestPath, operation)
}

func (npmRepository) classifyOperation(requestPath string, operation string) Request {
	segments := splitPath(requestPath)
	if len(segments) == 0 || strings.HasPrefix(segments[0], "-") {
		return Request{Kind: RequestUnknown, Ecosystem: EcosystemNPM, Operation: operation}
	}
	name, consumed := npmName(segments)
	if name == "" {
		return Request{Kind: RequestUnknown, Ecosystem: EcosystemNPM, Operation: operation}
	}
	remaining := segments[consumed:]
	if len(remaining) == 0 {
		return Request{Kind: RequestMetadata, Ecosystem: EcosystemNPM, Operation: operation, Name: name}
	}
	if len(remaining) == 2 && remaining[0] == "-" {
		version := npmTarballVersion(name, remaining[1])
		if version == "" {
			return Request{Kind: RequestUnknown, Ecosystem: EcosystemNPM, Operation: operation}
		}
		return Request{Kind: RequestArtifact, Ecosystem: EcosystemNPM, Operation: "download", Name: name, Version: version}
	}
	if remaining[0] == "-" || strings.HasSuffix(remaining[len(remaining)-1], ".tgz") {
		return Request{Kind: RequestUnknown, Ecosystem: EcosystemNPM, Operation: operation}
	}
	return Request{Kind: RequestMetadata, Ecosystem: EcosystemNPM, Operation: operation, Name: name}
}

func (npmRepository) prepareMetadataRequest(header http.Header) {
	if strings.Contains(header.Get("Accept"), "application/vnd.npm.install-v1+json") {
		header.Set("Accept", "application/json")
	}
}

func (npmRepository) filterMetadata(input MetadataInput) (FilterResult, error) {
	result, err := filterNPMMetadata(input)
	if err != nil {
		return FilterResult{Body: input.Body}, nil
	}
	return result, nil
}

func filterNPMMetadata(input MetadataInput) (FilterResult, error) {
	contentType, err := mediaType(input.ContentType)
	if err != nil || !isJSONMediaType(contentType) {
		return FilterResult{}, fmt.Errorf("unsupported npm metadata content type %q", contentType)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(input.Body, &document); err != nil {
		return FilterResult{}, fmt.Errorf("decode npm metadata: %w", err)
	}
	var versions map[string]json.RawMessage
	if err := json.Unmarshal(document["versions"], &versions); err != nil {
		return FilterResult{}, fmt.Errorf("decode npm versions: %w", err)
	}
	var releaseTimes map[string]string
	if err := json.Unmarshal(document["time"], &releaseTimes); err != nil {
		return FilterResult{}, fmt.Errorf("decode npm release times: %w", err)
	}
	var distTags map[string]string
	if err := json.Unmarshal(document["dist-tags"], &distTags); err != nil {
		return FilterResult{}, fmt.Errorf("decode npm distribution tags: %w", err)
	}
	name := input.Request.Name
	if rawName := document["name"]; len(rawName) > 0 {
		var declaredName string
		if json.Unmarshal(rawName, &declaredName) == nil && declaredName != "" {
			name = npmRepository{}.normalizeName(declaredName)
		}
	}
	denied := make(map[string]struct{})
	result := FilterResult{}
	orderedVersions := make([]string, 0, len(versions))
	for version := range versions {
		orderedVersions = append(orderedVersions, version)
	}
	sort.Strings(orderedVersions)
	for _, version := range orderedVersions {
		rawVersion := versions[version]
		candidate := Candidate{Ecosystem: EcosystemNPM, Operation: "resolve", Name: name, Version: version}
		if released, ok := parseReleaseTime(releaseTimes[version]); ok {
			candidate.RegistryReleased = &released
		}
		var versionDocument struct {
			Dist struct {
				Tarball string `json:"tarball"`
			} `json:"dist"`
		}
		if json.Unmarshal(rawVersion, &versionDocument) == nil && versionDocument.Dist.Tarball != "" {
			artifactCandidate := candidate
			artifactCandidate.Operation = "download"
			input.Artifacts.Observe(versionDocument.Dist.Tarball, artifactCandidate)
		}
		if input.tooYoung(candidate) {
			delete(versions, version)
			denied[version] = struct{}{}
			result.Suppressed++
		}
	}
	if len(denied) == 0 {
		result.Body = input.Body
		return result, nil
	}
	_, hadLatest := distTags["latest"]
	for tag, version := range distTags {
		if _, blocked := denied[version]; blocked {
			delete(distTags, tag)
		}
	}
	if _, hasLatest := distTags["latest"]; hadLatest && !hasLatest {
		if latest := npmLatestVersion(versions, releaseTimes); latest != "" {
			distTags["latest"] = latest
		}
	}
	encodedTags, err := json.Marshal(distTags)
	if err != nil {
		return FilterResult{}, err
	}
	document["dist-tags"] = encodedTags
	for version := range denied {
		delete(releaseTimes, version)
	}
	if releaseTimes != nil {
		encoded, err := json.Marshal(releaseTimes)
		if err != nil {
			return FilterResult{}, err
		}
		document["time"] = encoded
	}
	encodedVersions, err := json.Marshal(versions)
	if err != nil {
		return FilterResult{}, err
	}
	document["versions"] = encodedVersions
	result.Body, err = json.Marshal(document)
	if err != nil {
		return FilterResult{}, err
	}
	result.Modified = true
	return result, nil
}

func (npmRepository) feedPaths() FeedPaths {
	return FeedPaths{Malware: "malware_predictions.json", Release: "releases/npm.json"}
}

func npmName(segments []string) (string, int) {
	if len(segments) == 0 {
		return "", 0
	}
	if strings.HasPrefix(segments[0], "@") {
		if len(segments) < 2 || len(segments[0]) == 1 || segments[1] == "" {
			return "", 0
		}
		return strings.ToLower(segments[0] + "/" + segments[1]), 2
	}
	return strings.ToLower(segments[0]), 1
}

func npmTarballVersion(name string, filename string) string {
	if !strings.HasSuffix(filename, ".tgz") {
		return ""
	}
	baseName := name
	if slash := strings.LastIndexByte(baseName, '/'); slash >= 0 {
		baseName = baseName[slash+1:]
	}
	prefix := baseName + "-"
	if !strings.HasPrefix(filename, prefix) {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(filename, prefix), ".tgz")
}

func npmLatestVersion(versions map[string]json.RawMessage, releaseTimes map[string]string) string {
	ordered := make([]string, 0, len(versions))
	for version := range versions {
		if _, ok := releaseTimes[version]; ok {
			ordered = append(ordered, version)
		}
	}
	sort.Strings(ordered)
	latest := func(prerelease bool) string {
		candidate := ""
		candidateTime := ""
		for _, version := range ordered {
			if strings.Contains(version, "-") != prerelease {
				continue
			}
			if released := releaseTimes[version]; candidate == "" || released > candidateTime {
				candidate = version
				candidateTime = released
			}
		}
		return candidate
	}
	if stable := latest(false); stable != "" {
		return stable
	}
	return latest(true)
}
