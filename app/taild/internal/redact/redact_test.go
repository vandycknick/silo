package redact

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestLogRedactionIncludesAttrsErrorsAndLoginURL(t *testing.T) {
	var out bytes.Buffer
	log := slog.New(New(slog.NewJSONHandler(&out, nil), "opaque-secret"))
	log.With("config", "/etc/silo/config.yaml").Info("UserLogf tskey-auth-secret", "error", errors.New("https://secret:password@control.test/token?access_token=secret /home/operator/private opaque-secret"), "login", "https://login.tailscale.com/a/valid-login-link")
	text := out.String()
	for _, forbidden := range []string{"tskey-auth-secret", "opaque-secret", "/etc/silo", "/home/operator", "control.test", "password"} {
		if strings.Contains(text, forbidden) {
			t.Fatal("log leaked", forbidden, text)
		}
	}
	if !strings.Contains(text, "https://login.tailscale.com/a/valid-login-link") {
		t.Fatal("operator login URL hidden", text)
	}
}
