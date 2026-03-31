package main

import (
	"bytes"
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
			got := normalizeDomain(tt.input)
			if got != tt.want {
				t.Fatalf("normalizeDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFindRecordByPrefix(t *testing.T) {
	records := []string{
		"google-site-verification=abc",
		" v=SPF1 include:_spf.google.com ~all ",
		"other=record",
	}

	got, ok := findRecordByPrefix(records, "v=spf1")
	if !ok {
		t.Fatal("expected to find SPF record")
	}

	want := "v=SPF1 include:_spf.google.com ~all"
	if got != want {
		t.Fatalf("findRecordByPrefix() = %q, want %q", got, want)
	}

	_, ok = findRecordByPrefix(records, "v=DMARC1")
	if ok {
		t.Fatal("did not expect to find DMARC record")
	}
}

func TestNewResultWriterCSV(t *testing.T) {
	var buf bytes.Buffer

	w, err := newResultWriter("csv", &buf)
	if err != nil {
		t.Fatalf("newResultWriter(csv) error: %v", err)
	}

	if err := w.WriteHeader(); err != nil {
		t.Fatalf("WriteHeader() error: %v", err)
	}

	if err := w.WriteResult(domainResult{Domain: "example.com", HasMX: true, HasSPF: true}); err != nil {
		t.Fatalf("WriteResult() error: %v", err)
	}

	if err := w.Flush(); err != nil {
		t.Fatalf("Flush() error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "domain,hasMX,hasSPF,spfRecord,hasDMARC,dmarcRecord") {
		t.Fatalf("missing CSV header in output: %q", out)
	}
	if !strings.Contains(out, "example.com,true,true") {
		t.Fatalf("missing CSV row in output: %q", out)
	}
}

func TestNewResultWriterJSON(t *testing.T) {
	var buf bytes.Buffer

	w, err := newResultWriter("json", &buf)
	if err != nil {
		t.Fatalf("newResultWriter(json) error: %v", err)
	}

	if err := w.WriteHeader(); err != nil {
		t.Fatalf("WriteHeader() error: %v", err)
	}

	if err := w.WriteResult(domainResult{Domain: "example.com", HasDMARC: true, DMARCRecord: "v=DMARC1; p=none"}); err != nil {
		t.Fatalf("WriteResult() error: %v", err)
	}

	if err := w.Flush(); err != nil {
		t.Fatalf("Flush() error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"domain":"example.com"`) {
		t.Fatalf("missing domain in JSON output: %q", out)
	}
	if !strings.Contains(out, `"hasDMARC":true`) {
		t.Fatalf("missing hasDMARC in JSON output: %q", out)
	}
}

func TestNewResultWriterInvalidFormat(t *testing.T) {
	_, err := newResultWriter("xml", &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}
