package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"tailscale.com/envknob"
)

func TestBootstrapBeforeUpstreamInitialization(t *testing.T) {
	if os.Getenv("SILO_TAILD_BOOT_CHILD") == "1" {
		for _, name := range []string{"TS_AUTHKEY", "TS_CLIENT_SECRET", "TS_DEBUG_DISCO", "TS_DEBUG_MAGICSOCK_RING_BUFFER_MAX_SIZE_BYTES", "TS_DEBUG_RING_BUFFER_SIZE", "TSNET_FORCE_LOGIN", "SILO_NET_SECRET"} {
			if os.Getenv(name) != "" {
				t.Fatalf("ambient %s survived", name)
			}
		}
		if envknob.RegisterInt("TS_DEBUG_MAGICSOCK_RING_BUFFER_MAX_SIZE_BYTES")() != 0 || envknob.RegisterInt("TS_DEBUG_RING_BUFFER_SIZE")() != 0 || envknob.RegisterBool("TS_DEBUG_DISCO")() {
			t.Fatal("upstream cached ambient knob")
		}
		if os.Getenv("AWS_PROFILE") != "preserved" {
			t.Fatal("unrelated environment was removed")
		}
		return
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(exe, "-test.run=^TestBootstrapBeforeUpstreamInitialization$")
	cmd.Env = append(os.Environ(), "SILO_TAILD_BOOT_CHILD=1", "TS_AUTHKEY=sentinel", "TS_CLIENT_SECRET=sentinel", "TS_DEBUG_DISCO=invalid-bool", "TS_DEBUG_MAGICSOCK_RING_BUFFER_MAX_SIZE_BYTES=314159", "TS_DEBUG_RING_BUFFER_SIZE=271828", "TSNET_FORCE_LOGIN=1", "SILO_NET_SECRET=sentinel", "AWS_PROFILE=preserved", "GODEBUG=inittrace=1")
	output, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("%v\n%s", e, output)
	}
	text := string(output)
	boot := strings.Index(text, "init github.com/vandycknick/silo/app/taild/internal/bootenv ")
	upstream := strings.Index(text, "init tailscale.com/envknob ")
	if boot < 0 || upstream < 0 || boot >= upstream {
		t.Fatalf("bootstrap initialization order failed\n%s", text)
	}
}
