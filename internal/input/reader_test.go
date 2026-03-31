package input

import (
	"strings"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "trims and lowercase", input: "  ExAmPle.COM  ", want: "example.com"},
		{name: "empty stays empty", input: "   ", want: ""},
		{name: "already normalized", input: "mail.example.org", want: "mail.example.org"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeDomain(tt.input)
			if got != tt.want {
				t.Fatalf("NormalizeDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestReadDomains(t *testing.T) {
	in := strings.NewReader(" Example.com\n\n   \nGmail.com  \n")

	got, err := ReadDomains(in)
	if err != nil {
		t.Fatalf("ReadDomains() error: %v", err)
	}

	want := []string{"example.com", "gmail.com"}
	if len(got) != len(want) {
		t.Fatalf("ReadDomains() len = %d, want %d", len(got), len(want))
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ReadDomains()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
