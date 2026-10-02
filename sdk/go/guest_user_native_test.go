package silo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeGuestUserOptInAndReopen(t *testing.T) {
	r, home := phase7Runtime(t)
	ctx := context.Background()
	disk := filepath.Join(home, "input.raw")
	if err := os.WriteFile(disk, []byte("root-disk"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"default-root", "explicit-nickvd", "existing-silo"} {
		opts := []MachineOption{WithName(name)}
		var want *GuestUser
		if name != "default-root" {
			user := "nickvd"
			if name == "existing-silo" {
				user = "silo"
			}
			want = &GuestUser{Name: user, UID: 1000, GID: 1000, Home: "/home/" + user}
			opts = append(opts, WithGuestUser(want.Name, want.UID, want.GID, want.Home))
		}
		m, err := r.CreateMachine(ctx, DiskImage(disk), opts...)
		if err != nil {
			t.Fatal(err)
		}
		d, err := m.Inspect(ctx)
		_ = m.Close()
		if err != nil {
			t.Fatal(err)
		}
		if want == nil && d.GuestUser != nil || want != nil && (d.GuestUser == nil || *d.GuestUser != *want) {
			t.Fatalf("%s: %#v", name, d.GuestUser)
		}
		reopened, err := Open(ctx, WithHome(home), WithRuntimeRoot(os.Getenv("SILO_TEST_RUNTIME_ROOT")))
		if err != nil {
			t.Fatal(err)
		}
		m, err = reopened.Machine(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		d, err = m.Inspect(ctx)
		_ = m.Close()
		_ = reopened.Close()
		if err != nil {
			t.Fatal(err)
		}
		if want == nil && d.GuestUser != nil || want != nil && (d.GuestUser == nil || *d.GuestUser != *want) {
			t.Fatalf("reopened %s: %#v", name, d.GuestUser)
		}
	}
}
