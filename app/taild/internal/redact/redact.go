// Package redact is the final boundary for operator logs, never protocol data.
package redact

import (
	"context"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
)

var tokens = regexp.MustCompile(`(?i)(tskey-[a-z0-9-]+|(?:bearer|basic)\s+[^\s,;]+|(?:access_token|client_secret|authkey|token|password)["']?\s*[=:]\s*["']?[^\s,;"'}]+)`)
var urls = regexp.MustCompile(`https?://[^\s"<>]+`)
var paths = regexp.MustCompile(`(?:^|\s|[="'(])(/[^\s"')]+)`)

func Text(text string, secrets ...string) string {
	for _, secret := range secrets {
		if secret != "" {
			text = strings.ReplaceAll(text, secret, "[redacted]")
		}
	}
	text = tokens.ReplaceAllString(text, "[redacted]")
	// Login URLs intentionally reach the operator. API/control URLs and query
	// material do not. Temporarily shield an approved login URL from path removal.
	allowed := []string{}
	text = urls.ReplaceAllStringFunc(text, func(value string) string {
		u, err := url.Parse(value)
		if err == nil && u.Scheme == "https" && u.Host == "login.tailscale.com" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && (strings.HasPrefix(u.Path, "/a/") || strings.HasPrefix(u.Path, "/admin/auth/")) {
			allowed = append(allowed, value)
			return "TAILLOGINPLACEHOLDER" + strings.Repeat("X", len(allowed)) + "END"
		}
		return "[url]"
	})
	text = paths.ReplaceAllStringFunc(text, func(value string) string {
		idx := strings.IndexByte(value, '/')
		return value[:idx] + "[path]"
	})
	for j, value := range allowed {
		text = strings.ReplaceAll(text, "TAILLOGINPLACEHOLDER"+strings.Repeat("X", j+1)+"END", value)
	}
	return text
}

type Handler struct {
	next    slog.Handler
	secrets []string
}

func New(next slog.Handler, secrets ...string) slog.Handler {
	return &Handler{next: next, secrets: secrets}
}
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}
func (h *Handler) attr(a slog.Attr) slog.Attr {
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindGroup:
		a.Value = slog.GroupValue(h.attrs(v.Group())...)
	case slog.KindString, slog.KindAny:
		a.Value = slog.StringValue(Text(v.String(), h.secrets...))
	}
	return a
}
func (h *Handler) Handle(ctx context.Context, record slog.Record) error {
	r := slog.NewRecord(record.Time, record.Level, Text(record.Message, h.secrets...), record.PC)
	record.Attrs(func(a slog.Attr) bool { r.AddAttrs(h.attr(a)); return true })
	return h.next.Handle(ctx, r)
}
func (h *Handler) attrs(attrs []slog.Attr) []slog.Attr {
	redacted := make([]slog.Attr, len(attrs))
	for j, a := range attrs {
		redacted[j] = h.attr(a)
	}
	return redacted
}
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &Handler{h.next.WithAttrs(h.attrs(attrs)), h.secrets}
}
func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{h.next.WithGroup(name), h.secrets}
}
