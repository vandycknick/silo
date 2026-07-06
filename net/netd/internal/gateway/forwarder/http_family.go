package forwarder

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/vandycknick/silo/net/netd/internal/credentials"
	"github.com/vandycknick/silo/net/netd/internal/gateway/hooks"
)

const maxHTTPResponseHeaderBytes = 1 << 20

var errHTTPResponseHeaderTooLarge = errors.New("http response header too large")

type httpForwardOutcome struct {
	status         int
	reason         string
	responseHeader http.Header
}

var normalRequestStripHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
	"Cf-Worker",
	"Cf-Ray",
	"Cf-Ew-Via",
	"Cf-Connecting-Ip",
	"Cdn-Loop",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"Via",
}

var credentialResponseStripHeaders = []string{
	"Set-Cookie",
	"Set-Cookie2",
	"WWW-Authenticate",
	"Proxy-Authenticate",
	"Authentication-Info",
	"Proxy-Authentication-Info",
}

func forwardHTTPFamilyRequest(
	ctx context.Context,
	client net.Conn,
	clientReader *bufio.Reader,
	req *http.Request,
	scheme string,
	authority string,
	credentialManager *credentials.Manager,
	credential *hooks.Credential,
	dial func() (net.Conn, error),
) (httpForwardOutcome, error) {
	if isWebSocketUpgrade(req) {
		prepareWebSocketForwardRequest(req, scheme, authority)
		if err := applyHTTPFamilyCredential(ctx, req, credentialManager, credential); err != nil {
			logCredentialApplyError(req, credential, err)
			_ = req.Body.Close()
			return writeHTTPFamilyStatus(client, http.StatusBadGateway, credentials.FailureReason(err))
		}
		return proxyWebSocketUpgrade(client, clientReader, req, dial)
	}
	prepareNormalForwardRequest(req, scheme, authority)
	if err := applyHTTPFamilyCredential(ctx, req, credentialManager, credential); err != nil {
		logCredentialApplyError(req, credential, err)
		_ = req.Body.Close()
		return writeHTTPFamilyStatus(client, http.StatusBadGateway, credentials.FailureReason(err))
	}
	return proxyHTTPFamilyRoundTrip(client, req, dial)
}

func applyHTTPFamilyCredential(ctx context.Context, req *http.Request, manager *credentials.Manager, credential *hooks.Credential) error {
	if credential == nil {
		return nil
	}
	if manager == nil {
		return nil
	}
	return manager.Apply(ctx, req, credential)
}

func logCredentialApplyError(req *http.Request, credential *hooks.Credential, err error) {
	attrs := []any{
		"reason", credentials.FailureReason(err),
		"error", err,
		"method", req.Method,
		"host", req.Host,
		"path", requestPath(req),
	}
	if credential != nil {
		attrs = append(attrs, "credential_kind", credential.Kind, "credential_name", credential.Name)
	}
	slog.Error("credential application failed", attrs...)
}

func proxyHTTPFamilyRoundTrip(client net.Conn, req *http.Request, dial func() (net.Conn, error)) (httpForwardOutcome, error) {
	defer req.Body.Close()
	outbound, err := dial()
	if err != nil {
		return writeHTTPFamilyStatus(client, http.StatusBadGateway, "upstream_error")
	}
	defer outbound.Close()

	upstreamReader := bufio.NewReader(outbound)
	if err := req.Write(outbound); err != nil {
		return writeHTTPFamilyStatus(client, http.StatusBadGateway, "upstream_error")
	}

	resp, err := http.ReadResponse(upstreamReader, req)
	if err != nil {
		return writeHTTPFamilyStatus(client, http.StatusBadGateway, "upstream_error")
	}
	defer resp.Body.Close()
	sanitizeHTTPFamilyResponse(resp, true)
	return httpForwardOutcome{status: resp.StatusCode, responseHeader: resp.Header.Clone()}, resp.Write(client)
}

func proxyWebSocketUpgrade(client net.Conn, clientReader *bufio.Reader, req *http.Request, dial func() (net.Conn, error)) (httpForwardOutcome, error) {
	defer req.Body.Close()
	outbound, err := dial()
	if err != nil {
		return writeHTTPFamilyStatus(client, http.StatusBadGateway, "upstream_error")
	}
	defer outbound.Close()

	upstreamReader := bufio.NewReader(outbound)
	if err := req.Write(outbound); err != nil {
		return writeHTTPFamilyStatus(client, http.StatusBadGateway, "upstream_error")
	}

	rawHeader, err := readHTTPResponseHeader(upstreamReader)
	if err != nil {
		return writeHTTPFamilyStatus(client, http.StatusBadGateway, "upstream_error")
	}
	statusCode := statusCodeFromRawHTTPResponseHeader(rawHeader)
	if statusCode == 0 {
		return writeHTTPFamilyStatus(client, http.StatusBadGateway, "upstream_error")
	}
	sanitizedHeader := sanitizeRawHTTPResponseHeader(rawHeader)
	responseHeader := responseHeaderFromRawHTTPResponseHeader(sanitizedHeader, req)
	if _, err := client.Write(sanitizedHeader); err != nil {
		return httpForwardOutcome{status: statusCode, responseHeader: responseHeader}, err
	}
	if statusCode != http.StatusSwitchingProtocols {
		_, err := io.Copy(client, upstreamReader)
		return httpForwardOutcome{status: statusCode, responseHeader: responseHeader}, err
	}
	return httpForwardOutcome{status: statusCode, responseHeader: responseHeader}, relayOpaqueWebSocket(client, clientReader, outbound, upstreamReader)
}

func writeHTTPFamilyStatus(conn net.Conn, status int, reason string) (httpForwardOutcome, error) {
	return httpForwardOutcome{status: status, reason: reason, responseHeader: httpStatusHeader(status, reason)}, writeHTTPStatus(conn, status, reason)
}

func prepareNormalForwardRequest(req *http.Request, scheme string, authority string) {
	sanitizeNormalRequestHeaders(req.Header)
	prepareForwardRequest(req, scheme, authority)
}

func prepareWebSocketForwardRequest(req *http.Request, scheme string, authority string) {
	req.Header.Del("Proxy-Authorization")
	prepareForwardRequest(req, scheme, authority)
}

func prepareForwardRequest(req *http.Request, scheme string, authority string) {
	req.RequestURI = ""
	req.URL.Scheme = scheme
	req.URL.Host = authority
	req.Host = authority
}

func sanitizeNormalRequestHeaders(header http.Header) {
	for _, name := range connectionHeaderTokens(header) {
		header.Del(name)
	}
	for _, name := range normalRequestStripHeaders {
		header.Del(name)
	}
}

func sanitizeHTTPFamilyResponse(resp *http.Response, preserveBasicWWWAuthenticate bool) {
	sanitizeHTTPFamilyHeader(resp.Header, preserveBasicWWWAuthenticate)
	sanitizeHTTPFamilyHeader(resp.Trailer, false)
	if resp.Body != nil && resp.Body != http.NoBody {
		resp.Body = &trailerSanitizingBody{ReadCloser: resp.Body, trailer: resp.Trailer}
	}
}

type trailerSanitizingBody struct {
	io.ReadCloser
	trailer http.Header
}

func (b *trailerSanitizingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		sanitizeHTTPFamilyHeader(b.trailer, false)
	}
	return n, err
}

func (b *trailerSanitizingBody) Close() error {
	sanitizeHTTPFamilyHeader(b.trailer, false)
	return b.ReadCloser.Close()
}

func sanitizeHTTPFamilyHeader(header http.Header, preserveBasicWWWAuthenticate bool) {
	if header == nil {
		return
	}
	header.Del("Alt-Svc")
	for _, name := range credentialResponseStripHeaders {
		if preserveBasicWWWAuthenticate && strings.EqualFold(name, "WWW-Authenticate") {
			preserveBasicWWWAuthenticateHeader(header)
			continue
		}
		header.Del(name)
	}
}

func readHTTPResponseHeader(reader *bufio.Reader) ([]byte, error) {
	var header bytes.Buffer
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		if header.Len()+len(line) > maxHTTPResponseHeaderBytes {
			return nil, errHTTPResponseHeaderTooLarge
		}
		header.Write(line)
		if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
			return header.Bytes(), nil
		}
	}
}

func sanitizeRawHTTPResponseHeader(header []byte) []byte {
	lines := rawHeaderLines(header)
	if len(lines) == 0 {
		return header
	}
	var sanitized bytes.Buffer
	sanitized.Write(lines[0])
	droppingContinuation := false
	for _, line := range lines[1:] {
		if rawHeaderLineBlank(line) {
			sanitized.Write(line)
			droppingContinuation = false
			continue
		}
		if rawHeaderLineContinuation(line) {
			if !droppingContinuation {
				sanitized.Write(line)
			}
			continue
		}
		name, ok := rawHeaderFieldName(line)
		if ok && stripRawHTTPResponseHeader(name) {
			droppingContinuation = true
			continue
		}
		droppingContinuation = false
		sanitized.Write(line)
	}
	return sanitized.Bytes()
}

func responseHeaderFromRawHTTPResponseHeader(header []byte, req *http.Request) http.Header {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(header)), req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	return resp.Header.Clone()
}

func rawHeaderLines(header []byte) [][]byte {
	lines := make([][]byte, 0, bytes.Count(header, []byte("\n"))+1)
	for len(header) > 0 {
		newline := bytes.IndexByte(header, '\n')
		if newline == -1 {
			lines = append(lines, header)
			break
		}
		lines = append(lines, header[:newline+1])
		header = header[newline+1:]
	}
	return lines
}

func rawHeaderLineBlank(line []byte) bool {
	line = bytes.TrimRight(line, "\r\n")
	return len(line) == 0
}

func rawHeaderLineContinuation(line []byte) bool {
	return len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
}

func rawHeaderFieldName(line []byte) (string, bool) {
	colon := bytes.IndexByte(line, ':')
	if colon <= 0 {
		return "", false
	}
	name := strings.TrimSpace(string(line[:colon]))
	return name, name != ""
}

func stripRawHTTPResponseHeader(name string) bool {
	if strings.EqualFold(name, "Alt-Svc") {
		return true
	}
	for _, candidate := range credentialResponseStripHeaders {
		if strings.EqualFold(name, candidate) {
			return true
		}
	}
	return false
}

func statusCodeFromRawHTTPResponseHeader(header []byte) int {
	line, _, _ := bytes.Cut(header, []byte("\n"))
	fields := strings.Fields(strings.TrimRight(string(line), "\r"))
	if len(fields) < 2 {
		return 0
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return status
}

func preserveBasicWWWAuthenticateHeader(header http.Header) {
	values := header.Values("WWW-Authenticate")
	if len(values) == 0 {
		return
	}
	header.Del("WWW-Authenticate")
	for _, value := range values {
		for _, challenge := range basicWWWAuthenticateChallenges(value) {
			header.Add("WWW-Authenticate", challenge)
		}
	}
}

func basicWWWAuthenticateChallenges(value string) []string {
	var challenges []string
	for _, challenge := range splitWWWAuthenticateChallenges(value) {
		if strings.EqualFold(authChallengeScheme(challenge), "Basic") {
			challenges = append(challenges, challenge)
		}
	}
	return challenges
}

func splitWWWAuthenticateChallenges(value string) []string {
	parts := splitHeaderList(value)
	challenges := make([]string, 0, len(parts))
	current := ""
	for _, part := range parts {
		if part == "" {
			continue
		}
		if looksLikeAuthChallengeStart(part) {
			if current != "" {
				challenges = append(challenges, current)
			}
			current = part
			continue
		}
		if current == "" {
			current = part
		} else {
			current += ", " + part
		}
	}
	if current != "" {
		challenges = append(challenges, current)
	}
	return challenges
}

func splitHeaderList(value string) []string {
	var parts []string
	start := 0
	inQuote := false
	escaped := false
	for i, r := range value {
		switch {
		case escaped:
			escaped = false
		case r == '\\' && inQuote:
			escaped = true
		case r == '"':
			inQuote = !inQuote
		case r == ',' && !inQuote:
			parts = append(parts, strings.TrimSpace(value[start:i]))
			start = i + 1
		}
	}
	parts = append(parts, strings.TrimSpace(value[start:]))
	return parts
}

func looksLikeAuthChallengeStart(value string) bool {
	value = strings.TrimLeft(value, " \t")
	for i, r := range value {
		if r == ' ' || r == '\t' {
			return i > 0 && httpToken(value[:i])
		}
		if r == '=' {
			return false
		}
	}
	return value != "" && httpToken(value)
}

func authChallengeScheme(value string) string {
	value = strings.TrimLeft(value, " \t")
	for i, r := range value {
		if r == ' ' || r == '\t' {
			return value[:i]
		}
		if r == '=' {
			return ""
		}
	}
	return value
}

func httpToken(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !strings.ContainsRune("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", r) {
			return false
		}
	}
	return true
}

func isWebSocketUpgrade(req *http.Request) bool {
	return strings.EqualFold(req.Method, http.MethodGet) &&
		headerValuesContainToken(req.Header.Values("Connection"), "upgrade") &&
		strings.EqualFold(strings.TrimSpace(req.Header.Get("Upgrade")), "websocket")
}

func connectionHeaderTokens(header http.Header) []string {
	var tokens []string
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			token = strings.TrimSpace(token)
			if token != "" {
				tokens = append(tokens, token)
			}
		}
	}
	return tokens
}

func headerValuesContainToken(values []string, want string) bool {
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), want) {
				return true
			}
		}
	}
	return false
}

func relayOpaqueWebSocket(client net.Conn, clientReader *bufio.Reader, upstream net.Conn, upstreamReader *bufio.Reader) error {
	done := make(chan error, 2)
	go func() {
		_, err := io.Copy(upstream, clientReader)
		done <- err
	}()
	go func() {
		_, err := io.Copy(client, upstreamReader)
		done <- err
	}()
	<-done
	_ = upstream.Close()
	_ = client.Close()
	<-done
	return nil
}

func statusForReason(reason string) int {
	switch reason {
	case "missing_host":
		return http.StatusBadRequest
	case "host_mismatch":
		return http.StatusMisdirectedRequest
	case "upstream_error", "tunnel_not_connected", "tunnel_error", "credential_error", credentials.ReasonSecret, credentials.ReasonRefresh, credentials.ReasonSigning, credentials.ReasonInjection:
		return http.StatusBadGateway
	default:
		return http.StatusForbidden
	}
}
