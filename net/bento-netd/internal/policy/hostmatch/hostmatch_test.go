package hostmatch

import "testing"

func TestParseAuthorityNormalizesHTTPFamilyAuthorities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		defaultPort uint16
		want        Authority
		wantFormat  string
	}{
		{
			name:        "lowercase hostname",
			input:       "Example.COM",
			defaultPort: 80,
			want:        Authority{Host: "example.com", Port: 80},
			wantFormat:  "example.com",
		},
		{
			name:        "strip trailing dot",
			input:       "Example.COM.",
			defaultPort: 80,
			want:        Authority{Host: "example.com", Port: 80},
			wantFormat:  "example.com",
		},
		{
			name:        "default port normalizes away",
			input:       "example.com:80",
			defaultPort: 80,
			want:        Authority{Host: "example.com", Port: 80},
			wantFormat:  "example.com",
		},
		{
			name:        "explicit non default port",
			input:       "example.com:8080",
			defaultPort: 80,
			want:        Authority{Host: "example.com", Port: 8080},
			wantFormat:  "example.com:8080",
		},
		{
			name:        "IPv4 literal",
			input:       "192.0.2.10:8080",
			defaultPort: 80,
			want:        Authority{Host: "192.0.2.10", Port: 8080},
			wantFormat:  "192.0.2.10:8080",
		},
		{
			name:        "bracketed IPv6 default port",
			input:       "[2001:db8::1]",
			defaultPort: 443,
			want:        Authority{Host: "2001:db8::1", Port: 443},
			wantFormat:  "[2001:db8::1]",
		},
		{
			name:        "bracketed IPv6 explicit port",
			input:       "[2001:db8::1]:8443",
			defaultPort: 443,
			want:        Authority{Host: "2001:db8::1", Port: 8443},
			wantFormat:  "[2001:db8::1]:8443",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseAuthority(test.input, test.defaultPort)
			if err != nil {
				t.Fatalf("ParseAuthority() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("ParseAuthority() = %#v, want %#v", got, test.want)
			}
			if gotFormat := FormatAuthority(got, test.defaultPort); gotFormat != test.wantFormat {
				t.Fatalf("FormatAuthority() = %q, want %q", gotFormat, test.wantFormat)
			}
		})
	}
}

func TestParseAuthorityRejectsInvalidAuthorities(t *testing.T) {
	t.Parallel()

	tests := []string{
		"",
		"https://example.com",
		"example.com/path",
		"example.com?x=1",
		"example.com#frag",
		"user@example.com",
		"user:pass@example.com",
		"example.com:",
		"example.com:0",
		"example.com:65536",
		"example.com:abc",
		"exa mple.com",
		"exämple.com",
		"2001:db8::1",
		"[192.0.2.10]",
		"[example.com]",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			t.Parallel()

			if got, err := ParseAuthority(input, 80); err == nil {
				t.Fatalf("ParseAuthority() = %#v, want error", got)
			}
		})
	}
}

func TestParseBindingCanonicalizesEndpointHosts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		defaultPort uint16
		want        Binding
	}{
		{
			name:        "exact default port",
			input:       "Example.COM:80",
			defaultPort: 80,
			want:        Binding{Pattern: "example.com", Host: "example.com", Port: 80},
		},
		{
			name:        "exact explicit port",
			input:       "Example.COM:8080",
			defaultPort: 80,
			want:        Binding{Pattern: "example.com:8080", Host: "example.com", Port: 8080},
		},
		{
			name:        "wildcard explicit port",
			input:       "*.Example.COM:8080",
			defaultPort: 80,
			want:        Binding{Pattern: "*.example.com:8080", Host: "example.com", Port: 8080, Wildcard: true},
		},
		{
			name:        "IPv6 exact default port",
			input:       "[2001:db8::1]",
			defaultPort: 443,
			want:        Binding{Pattern: "[2001:db8::1]", Host: "2001:db8::1", Port: 443},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseBinding(test.input, test.defaultPort)
			if err != nil {
				t.Fatalf("ParseBinding() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("ParseBinding() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestParseBindingRejectsInvalidWildcards(t *testing.T) {
	t.Parallel()

	tests := []string{
		"*example.com",
		"*.",
		"example.*.com",
		"*.192.0.2.10",
		"*.168.1.1",
		"*.[2001:db8::1]",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			t.Parallel()

			if got, err := ParseBinding(input, 80); err == nil {
				t.Fatalf("ParseBinding() = %#v, want error", got)
			}
		})
	}
}

func TestBindingMatchesExactAndWildcardAuthorities(t *testing.T) {
	t.Parallel()

	exact, err := ParseBinding("example.com:8080", 80)
	if err != nil {
		t.Fatalf("ParseBinding(exact) error = %v", err)
	}
	wildcard, err := ParseBinding("*.example.com", 80)
	if err != nil {
		t.Fatalf("ParseBinding(wildcard) error = %v", err)
	}

	tests := []struct {
		name      string
		binding   Binding
		authority Authority
		want      bool
	}{
		{
			name:      "exact same host and port",
			binding:   exact,
			authority: Authority{Host: "example.com", Port: 8080},
			want:      true,
		},
		{
			name:      "exact wrong port",
			binding:   exact,
			authority: Authority{Host: "example.com", Port: 80},
		},
		{
			name:      "wildcard descendant",
			binding:   wildcard,
			authority: Authority{Host: "api.example.com", Port: 80},
			want:      true,
		},
		{
			name:      "wildcard deep descendant",
			binding:   wildcard,
			authority: Authority{Host: "a.b.example.com", Port: 80},
			want:      true,
		},
		{
			name:      "wildcard excludes apex",
			binding:   wildcard,
			authority: Authority{Host: "example.com", Port: 80},
		},
		{
			name:      "wildcard requires label boundary",
			binding:   wildcard,
			authority: Authority{Host: "badexample.com", Port: 80},
		},
		{
			name:      "wildcard wrong port",
			binding:   wildcard,
			authority: Authority{Host: "api.example.com", Port: 8080},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := test.binding.Matches(test.authority); got != test.want {
				t.Fatalf("Matches() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestParsePort(t *testing.T) {
	t.Parallel()

	valid := []struct {
		input string
		want  uint16
	}{
		{input: "1", want: 1},
		{input: "80", want: 80},
		{input: "65535", want: 65535},
	}
	for _, test := range valid {
		t.Run("valid "+test.input, func(t *testing.T) {
			t.Parallel()

			got, err := ParsePort(test.input)
			if err != nil {
				t.Fatalf("ParsePort() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("ParsePort() = %d, want %d", got, test.want)
			}
		})
	}

	invalid := []string{"", "0", "65536", "http", "80/tcp"}
	for _, input := range invalid {
		t.Run("invalid "+input, func(t *testing.T) {
			t.Parallel()

			if got, err := ParsePort(input); err == nil {
				t.Fatalf("ParsePort() = %d, want error", got)
			}
		})
	}
}
