package commands

import (
	"strings"
	"testing"
)

func TestCopyHandlerGrammar(t *testing.T) {
	for _, tc := range []struct {
		tokens []string
		want   string
	}{
		{[]string{"cp", "-", "-"}, "cp requires a VM endpoint (VM:/path)"},
		{[]string{"cp", "./in.bin", "vm:/root/x"}, "the lobby has no access to your files; use - and redirect stdin/stdout"},
		{[]string{"cp", "-", "vm:relative"}, "guest paths must be absolute (VM:/path)"},
		{[]string{"cp", "--mode", "8", "-", "vm:/x"}, "invalid value for --mode"},
		{[]string{"cp", "--owner", "1000:", "-", "vm:/x"}, "invalid value for --owner"},
		{[]string{"cp", "vm:/x", "other:/x"}, "cp copies between the host and one VM"},
		{[]string{"cp", "vm:/x", "-", "--parents"}, "upload-only"},
		{[]string{"cp", "--json", "vm:/x", "-"}, "--json is not supported"},
		{[]string{"cp", "-", "vm:/x", "--"}, "cp does not accept literal arguments after --"},
	} {
		t.Run(strings.Join(tc.tokens, " "), func(t *testing.T) {
			_, e := Execute(&Context{Context: t.Context()}, tc.tokens)
			if e == nil || !strings.Contains(e.Error(), tc.want) {
				t.Fatalf("got %v, want %q", e, tc.want)
			}
		})
	}
}
func TestCopyEndpointAndOptions(t *testing.T) {
	for _, s := range []string{"./file:part", "/file:part", "file"} {
		e, err := parseEndpoint(s)
		if err != nil || e.VM != "" || e.Stdio || e.Path != s {
			t.Fatal(s, e, err)
		}
	}
	for _, s := range []string{":/x", "vm:/x:y"} {
		if _, e := parseEndpoint(s); e == nil || !strings.Contains(e.Error(), "ambiguous endpoint") {
			t.Fatal(s, e)
		}
	}
	mode, e := parseOctalMode("0755")
	if e != nil || mode != 0755 {
		t.Fatal(mode, e)
	}
	uid, gid, e := parseOwner("1000")
	if e != nil || uid != 1000 || gid != nil {
		t.Fatal(uid, gid, e)
	}
	uid, gid, e = parseOwner("1000:1001")
	if e != nil || uid != 1000 || gid == nil || *gid != 1001 {
		t.Fatal(uid, gid, e)
	}
	for _, s := range []string{"-1", "+1", "4294967296", "1:2:3"} {
		if _, _, e := parseOwner(s); e == nil {
			t.Fatal(s)
		}
	}
	f := flagsOf(cp)
	if _, e := f.Parse([]string{"-p", "--parents"}); e == nil {
		t.Fatal("aliases must share occurrence budget")
	}
}
