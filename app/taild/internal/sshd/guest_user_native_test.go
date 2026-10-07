package sshd

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/service"
)

func TestNativeCreateProvisionUserParser(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, caller, registry := nativeService(t, "guest-user-parser", "user:7")
	p := caller.Peer
	r := s.Runtime
	for _, flags := range []string{"--provision-user", "--provision-user nickvd", "--provision-user root:0:0:/root", "--provision-user nickvd:1000:1000:/home/x:extra", "--provision-user nickvd:1000:1000:/home/x --provision-user other:1001:1001:/home/y"} {
		if code := DispatchSession(ctx, s, caller, "create "+registry.Reference+" --name invalid-user --no-start "+flags, service.IO{Stdout: io.Discard, Stderr: io.Discard}); code != 2 {
			t.Fatalf("%s: %d", flags, code)
		}
	}
	if len(s.Jobs.List(p)) != 0 {
		t.Fatal("invalid create admitted jobs")
	}
	if registry.Requests.Load() != 0 {
		t.Fatal("invalid account pulled a VM image")
	}
	for _, test := range []struct{ name, flags, user string }{{"default-root", "", ""}, {"opt-in", "--provision-user nickvd:1000:1000:/home/nickvd", "nickvd"}} {
		if code := DispatchSession(ctx, s, caller, "create "+registry.Reference+" --name "+test.name+" --no-start "+test.flags, service.IO{Stdout: io.Discard, Stderr: io.Discard}); code != 0 {
			t.Fatal(test.name, code)
		}
		d, err := r.Control.Inspect(ctx, test.name)
		if err != nil {
			t.Fatal(err)
		}
		if test.user == "" && d.GuestUser != nil || test.user != "" && (d.GuestUser == nil || d.GuestUser.Name != test.user || d.GuestUser.UID != 1000 || d.GuestUser.Home != "/home/nickvd") {
			t.Fatal(test.name, d.GuestUser)
		}
	}
}
