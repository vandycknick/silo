package main

import (
	"os"
	"reflect"
	"testing"
)

func TestAmbientTailscaleEnvironmentIsolationPreservesAWS(t *testing.T) {
	input := []string{"TS_AUTHKEY=bad", "TS_AUTH_KEY=bad", "TS_CLIENT_SECRET=bad", "TSNET_FORCE_LOGIN=1", "TS_OTHER=bad", "TSNET_OTHER=bad", "SILO_NET_SECRET_OLD=bad", "AWS_PROFILE=ordinary", "AWS_REGION=eu-west-1", "PATH=/bin"}
	want := []string{"AWS_PROFILE=ordinary", "AWS_REGION=eu-west-1", "PATH=/bin"}
	if got := sanitizedEnvironment(input); !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
	for _, name := range []string{"TS_AUTHKEY", "TSNET_FORCE_LOGIN", "TS_CLIENT_SECRET", "SILO_NET_SECRET_OLD"} {
		t.Setenv(name, "bad")
	}
	t.Setenv("AWS_PROFILE", "ordinary")
	if err := sanitizeLegacyEnvironment(); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("TS_AUTHKEY") != "" || os.Getenv("TSNET_FORCE_LOGIN") != "" || os.Getenv("TS_CLIENT_SECRET") != "" || os.Getenv("SILO_NET_SECRET_OLD") != "" || os.Getenv("AWS_PROFILE") != "ordinary" {
		t.Fatal("foreground environment isolation failed")
	}
}
