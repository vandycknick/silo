package registry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/html"
)

type pypiRepository struct{}

func (pypiRepository) ecosystem() Ecosystem {
	return EcosystemPyPI
}

func (pypiRepository) hosts() []string {
	return []string{"pypi.org", "files.pythonhosted.org", "pypi.python.org", "pythonhosted.org"}
}

func (pypiRepository) normalizeName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var normalized strings.Builder
	lastSeparator := false
	for _, character := range name {
		separator := character == '-' || character == '_' || character == '.'
		if separator {
			if !lastSeparator {
				normalized.WriteByte('-')
			}
		} else {
			normalized.WriteRune(character)
		}
		lastSeparator = separator
	}
	return normalized.String()
}

func (r pypiRepository) classify(method string, host string, requestPath string) Request {
	operation := requestOperation(method)
	host = normalizeHost(host)
	if decoded, err := url.PathUnescape(requestPath); err == nil {
		requestPath = decoded
	}
	segments := splitPath(requestPath)
	if len(segments) >= 2 && segments[0] == "simple" {
		return Request{Kind: RequestMetadata, Ecosystem: EcosystemPyPI, Operation: operation, Name: r.normalizeName(segments[1])}
	}
	if len(segments) >= 3 && segments[0] == "pypi" && segments[len(segments)-1] == "json" {
		return Request{Kind: RequestMetadata, Ecosystem: EcosystemPyPI, Operation: operation, Name: r.normalizeName(segments[1])}
	}
	name, version := pypiArtifactIdentity(path.Base(requestPath))
	if name != "" && version != "" {
		return Request{Kind: RequestArtifact, Ecosystem: EcosystemPyPI, Operation: "download", Name: r.normalizeName(name), Version: version}
	}
	return Request{Kind: RequestUnknown, Ecosystem: EcosystemPyPI, Operation: operation}
}

func (pypiRepository) prepareMetadataRequest(header http.Header) {
	header.Del("If-None-Match")
	header.Del("If-Modified-Since")
}

func (pypiRepository) filterMetadata(input MetadataInput) (FilterResult, error) {
	contentType, err := mediaType(input.ContentType)
	if err != nil {
		return FilterResult{Body: input.Body}, nil
	}
	var result FilterResult
	switch contentType {
	case "application/json", "application/vnd.pypi.simple.v1+json":
		result, err = filterPyPIMetadataJSON(input)
	case "text/html", "application/vnd.pypi.simple.v1+html":
		result, err = filterPyPISimpleHTML(input)
	default:
		return FilterResult{Body: input.Body}, nil
	}
	if err != nil {
		return FilterResult{Body: input.Body}, nil
	}
	return result, nil
}

func (pypiRepository) feedPaths() FeedPaths {
	return FeedPaths{Malware: "malware_pypi.json", Release: "releases/pypi.json"}
}

func filterPyPISimpleJSON(input MetadataInput) (FilterResult, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(input.Body, &document); err != nil {
		return FilterResult{}, fmt.Errorf("decode PyPI simple metadata: %w", err)
	}
	var files []map[string]json.RawMessage
	if err := json.Unmarshal(document["files"], &files); err != nil {
		return FilterResult{}, fmt.Errorf("decode PyPI files: %w", err)
	}
	type fileCandidate struct {
		file         map[string]json.RawMessage
		candidate    Candidate
		artifact     string
		coreMetadata bool
	}
	candidates := make([]fileCandidate, 0, len(files))
	for _, file := range files {
		filename := jsonString(file["filename"])
		version := pypiFilenameVersion(input.Request.Name, filename)
		candidate := Candidate{Ecosystem: EcosystemPyPI, Operation: "resolve", Name: input.Request.Name, Version: version}
		if released, ok := parseReleaseTime(jsonString(file["upload-time"])); ok {
			candidate.RegistryReleased = &released
		}
		candidates = append(candidates, fileCandidate{
			file:         file,
			candidate:    candidate,
			artifact:     resolveURL(input.URL, jsonString(file["url"])),
			coreMetadata: pyPICoreMetadataAvailable(file),
		})
	}
	packages := make([]Candidate, 0, len(candidates))
	for _, file := range candidates {
		packages = append(packages, file.candidate)
	}
	decisions := evaluatePyPIVersions(packages, input)
	result := FilterResult{}
	result.Suppressed = suppressedPyPIVersions(decisions)
	filtered := make([]map[string]json.RawMessage, 0, len(files))
	modified := false
	for _, file := range candidates {
		if file.candidate.Version == "" {
			filtered = append(filtered, file.file)
			continue
		}
		artifactCandidate := file.candidate
		artifactCandidate.Operation = "download"
		observePyPIArtifact(input.Artifacts, file.artifact, artifactCandidate, file.coreMetadata)
		blocked, ok := decisions[file.candidate.Version]
		if !ok {
			blocked = input.tooYoung(file.candidate)
			decisions[file.candidate.Version] = blocked
			if blocked {
				result.Suppressed++
			}
		}
		if blocked {
			modified = true
			continue
		}
		filtered = append(filtered, file.file)
	}
	var advertisedVersions []string
	if json.Unmarshal(document["versions"], &advertisedVersions) == nil {
		filteredVersions := advertisedVersions[:0]
		for _, version := range advertisedVersions {
			if !decisions[version] {
				filteredVersions = append(filteredVersions, version)
			}
		}
		if len(filteredVersions) != len(advertisedVersions) {
			encodedVersions, err := json.Marshal(filteredVersions)
			if err != nil {
				return FilterResult{}, err
			}
			document["versions"] = encodedVersions
			modified = true
		}
	}
	if !modified {
		result.Body = input.Body
		return result, nil
	}
	encodedFiles, err := json.Marshal(filtered)
	if err != nil {
		return FilterResult{}, err
	}
	document["files"] = encodedFiles
	result.Body, err = json.Marshal(document)
	if err != nil {
		return FilterResult{}, err
	}
	result.Modified = true
	return result, nil
}

func filterPyPIMetadataJSON(input MetadataInput) (FilterResult, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(input.Body, &document); err != nil {
		return FilterResult{}, fmt.Errorf("decode PyPI metadata: %w", err)
	}
	if len(document["files"]) > 0 {
		return filterPyPISimpleJSON(input)
	}
	var releases map[string][]map[string]json.RawMessage
	_ = json.Unmarshal(document["releases"], &releases)
	type releaseFile struct {
		version      string
		candidate    Candidate
		artifact     string
		coreMetadata bool
	}
	var files []releaseFile
	appendFiles := func(version string, entries []map[string]json.RawMessage) {
		for _, fields := range entries {
			candidate := Candidate{Ecosystem: EcosystemPyPI, Operation: "resolve", Name: input.Request.Name, Version: version}
			if released, ok := parseReleaseTime(jsonString(fields["upload_time_iso_8601"])); ok {
				candidate.RegistryReleased = &released
			}
			files = append(files, releaseFile{
				version:      version,
				candidate:    candidate,
				artifact:     resolveURL(input.URL, jsonString(fields["url"])),
				coreMetadata: pyPICoreMetadataAvailable(fields),
			})
		}
	}
	versions := make([]string, 0, len(releases))
	for version := range releases {
		versions = append(versions, version)
	}
	sort.Strings(versions)
	for _, version := range versions {
		appendFiles(version, releases[version])
	}
	var urls []map[string]json.RawMessage
	_ = json.Unmarshal(document["urls"], &urls)
	var info map[string]json.RawMessage
	_ = json.Unmarshal(document["info"], &info)
	if len(releases) == 0 {
		for _, fields := range urls {
			version := pypiMetadataFileVersion(input.Request.Name, fields)
			if version != "" {
				appendFiles(version, []map[string]json.RawMessage{fields})
			}
		}
	}
	candidatesByVersion := make(map[string]Candidate, len(versions))
	for _, file := range files {
		existing, ok := candidatesByVersion[file.version]
		if !ok || (file.candidate.RegistryReleased != nil && (existing.RegistryReleased == nil || file.candidate.RegistryReleased.Before(*existing.RegistryReleased))) {
			candidatesByVersion[file.version] = file.candidate
		}
	}
	if len(versions) == 0 {
		for version := range candidatesByVersion {
			versions = append(versions, version)
		}
		sort.Strings(versions)
	}
	packages := make([]Candidate, 0, len(versions))
	for _, version := range versions {
		candidate, ok := candidatesByVersion[version]
		if !ok {
			candidate = Candidate{Ecosystem: EcosystemPyPI, Operation: "resolve", Name: input.Request.Name, Version: version}
		}
		packages = append(packages, candidate)
	}
	decisions := evaluatePyPIVersions(packages, input)
	result := FilterResult{}
	result.Suppressed = suppressedPyPIVersions(decisions)
	modified := false
	for _, file := range files {
		artifactCandidate := file.candidate
		artifactCandidate.Operation = "download"
		observePyPIArtifact(input.Artifacts, file.artifact, artifactCandidate, file.coreMetadata)
	}
	if releases != nil {
		for version := range releases {
			blocked, ok := decisions[version]
			if ok && blocked {
				delete(releases, version)
				modified = true
			}
		}
		if modified {
			encoded, err := json.Marshal(releases)
			if err != nil {
				return FilterResult{}, err
			}
			document["releases"] = encoded
		}
	}
	if len(urls) > 0 {
		filteredURLs := make([]map[string]json.RawMessage, 0, len(urls))
		for _, fields := range urls {
			version := pypiMetadataFileVersion(input.Request.Name, fields)
			blocked, ok := decisions[version]
			if version == "" || !ok || !blocked {
				filteredURLs = append(filteredURLs, fields)
				continue
			}
			modified = true
		}
		if len(filteredURLs) != len(urls) {
			encoded, err := json.Marshal(filteredURLs)
			if err != nil {
				return FilterResult{}, err
			}
			document["urls"] = encoded
		}
	}
	if info != nil {
		infoVersion := jsonString(info["version"])
		if blocked, ok := decisions[infoVersion]; infoVersion != "" && ok && blocked {
			redactedInfo := make(map[string]json.RawMessage, 1)
			if name := info["name"]; len(name) > 0 {
				redactedInfo["name"] = name
			}
			encodedInfo, err := json.Marshal(redactedInfo)
			if err != nil {
				return FilterResult{}, err
			}
			document["info"] = encodedInfo
			if _, exists := document["vulnerabilities"]; exists {
				document["vulnerabilities"] = json.RawMessage(`[]`)
			}
			modified = true
		}
	}
	if !modified {
		result.Body = input.Body
		return result, nil
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return FilterResult{}, err
	}
	result.Body = encoded
	result.Modified = true
	return result, nil
}

func filterPyPISimpleHTML(input MetadataInput) (FilterResult, error) {
	document, err := html.Parse(bytes.NewReader(input.Body))
	if err != nil {
		return FilterResult{}, fmt.Errorf("decode PyPI simple HTML: %w", err)
	}
	type linkCandidate struct {
		node         *html.Node
		candidate    Candidate
		artifact     string
		coreMetadata bool
	}
	var links []linkCandidate
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "a" {
			href := htmlAttribute(node, "href")
			artifact := resolveURL(input.URL, href)
			filename := path.Base(strings.TrimSuffix(strings.Split(href, "#")[0], "/"))
			version := pypiFilenameVersion(input.Request.Name, filename)
			candidate := Candidate{Ecosystem: EcosystemPyPI, Operation: "resolve", Name: input.Request.Name, Version: version}
			if released, ok := parseReleaseTime(htmlAttribute(node, "data-upload-time")); ok {
				candidate.RegistryReleased = &released
			}
			links = append(links, linkCandidate{
				node:         node,
				candidate:    candidate,
				artifact:     artifact,
				coreMetadata: pyPIHTMLCoreMetadataAvailable(node),
			})
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(document)
	packages := make([]Candidate, 0, len(links))
	for _, link := range links {
		packages = append(packages, link.candidate)
	}
	decisions := evaluatePyPIVersions(packages, input)
	result := FilterResult{}
	result.Suppressed = suppressedPyPIVersions(decisions)
	modified := false
	for _, link := range links {
		if link.candidate.Version == "" {
			continue
		}
		artifactCandidate := link.candidate
		artifactCandidate.Operation = "download"
		observePyPIArtifact(input.Artifacts, link.artifact, artifactCandidate, link.coreMetadata)
		blocked, ok := decisions[link.candidate.Version]
		if !ok {
			blocked = input.tooYoung(link.candidate)
			decisions[link.candidate.Version] = blocked
			if blocked {
				result.Suppressed++
			}
		}
		if blocked {
			link.node.Parent.RemoveChild(link.node)
			modified = true
		}
	}
	if !modified {
		result.Body = input.Body
		return result, nil
	}
	var encoded bytes.Buffer
	if err := html.Render(&encoded, document); err != nil {
		return FilterResult{}, err
	}
	result.Body = encoded.Bytes()
	result.Modified = true
	return result, nil
}

func pypiFilenameVersion(packageName string, filename string) string {
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return ""
	}
	normalize := pypiRepository{}.normalizeName
	if strings.HasSuffix(filename, ".whl") {
		parts := strings.Split(strings.TrimSuffix(filename, ".whl"), "-")
		if len(parts) >= 5 && normalize(parts[0]) == normalize(packageName) {
			return parts[1]
		}
	}
	for _, suffix := range []string{".tar.gz", ".tar.bz2", ".tar.xz", ".zip", ".tgz"} {
		if !strings.HasSuffix(filename, suffix) {
			continue
		}
		base := strings.TrimSuffix(filename, suffix)
		for index := strings.IndexByte(base, '-'); index >= 0; {
			if normalize(base[:index]) == normalize(packageName) {
				return base[index+1:]
			}
			next := strings.IndexByte(base[index+1:], '-')
			if next < 0 {
				break
			}
			index += next + 1
		}
	}
	return ""
}

func pypiMetadataFileVersion(packageName string, fields map[string]json.RawMessage) string {
	if rawURL := jsonString(fields["url"]); rawURL != "" {
		if parsed, err := url.Parse(rawURL); err == nil {
			if version := pypiFilenameVersion(packageName, path.Base(parsed.Path)); version != "" {
				return version
			}
		}
	}
	return pypiFilenameVersion(packageName, jsonString(fields["filename"]))
}

func pypiArtifactIdentity(filename string) (string, string) {
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return "", ""
	}
	if strings.HasSuffix(filename, ".metadata") {
		filename = strings.TrimSuffix(filename, ".metadata")
	}
	if strings.HasSuffix(filename, ".whl") {
		base := strings.TrimSuffix(filename, ".whl")
		firstDash := strings.IndexByte(base, '-')
		if firstDash <= 0 {
			return "", ""
		}
		name := base[:firstDash]
		remainder := base[firstDash+1:]
		if secondDash := strings.IndexByte(remainder, '-'); secondDash >= 0 {
			remainder = remainder[:secondDash]
		}
		if remainder == "" || remainder == "latest" {
			return "", ""
		}
		return name, remainder
	}
	lowerFilename := strings.ToLower(filename)
	for _, suffix := range []string{".tar.gz", ".zip", ".tar.bz2", ".tar.xz"} {
		if !strings.HasSuffix(lowerFilename, suffix) {
			continue
		}
		base := filename[:len(filename)-len(suffix)]
		lastDash := strings.LastIndexByte(base, '-')
		if lastDash <= 0 || lastDash == len(base)-1 {
			return "", ""
		}
		name, version := base[:lastDash], base[lastDash+1:]
		if version == "latest" {
			return "", ""
		}
		return name, version
	}
	return "", ""
}

func evaluatePyPIVersions(candidates []Candidate, input MetadataInput) map[string]bool {
	outcomes := make(map[string]bool)
	for _, candidate := range candidates {
		if candidate.Version == "" {
			continue
		}
		if _, exists := outcomes[candidate.Version]; exists {
			continue
		}
		outcomes[candidate.Version] = input.tooYoung(candidate)
	}
	return outcomes
}

func suppressedPyPIVersions(decisions map[string]bool) int {
	suppressed := 0
	for _, blocked := range decisions {
		if blocked {
			suppressed++
		}
	}
	return suppressed
}

func parseReleaseTime(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return parsed, err == nil
}

func pyPICoreMetadataAvailable(fields map[string]json.RawMessage) bool {
	raw, exists := fields["core-metadata"]
	if !exists {
		raw, exists = fields["dist-info-metadata"]
	}
	if !exists {
		return false
	}
	var available bool
	if json.Unmarshal(raw, &available) == nil {
		return available
	}
	var hashes map[string]string
	if json.Unmarshal(raw, &hashes) == nil {
		return true
	}
	var hash string
	return json.Unmarshal(raw, &hash) == nil && hash != ""
}

func pyPIHTMLCoreMetadataAvailable(node *html.Node) bool {
	for _, attribute := range node.Attr {
		if attribute.Key == "data-core-metadata" {
			return true
		}
	}
	for _, attribute := range node.Attr {
		if attribute.Key == "data-dist-info-metadata" {
			return true
		}
	}
	return false
}

func observePyPIArtifact(index *ArtifactIndex, rawURL string, candidate Candidate, coreMetadata bool) {
	index.Observe(rawURL, candidate)
	if !coreMetadata {
		return
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Path == "" {
		return
	}
	parsed.Path += ".metadata"
	parsed.RawPath = ""
	parsed.Fragment = ""
	index.Observe(parsed.String(), candidate)
}

func jsonString(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}

func htmlAttribute(node *html.Node, name string) string {
	for _, attribute := range node.Attr {
		if attribute.Key == name {
			return attribute.Val
		}
	}
	return ""
}

func resolveURL(baseURL *url.URL, reference string) string {
	parsed, err := url.Parse(reference)
	if err != nil {
		return ""
	}
	if baseURL != nil {
		parsed = baseURL.ResolveReference(parsed)
	}
	return parsed.String()
}
