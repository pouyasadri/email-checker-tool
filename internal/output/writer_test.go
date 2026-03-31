package output

import (
	"bytes"
	"strings"
	"testing"

	"email-checker-tool/internal/checker"
)

func TestNewWriterCSV(t *testing.T) {
	var buf bytes.Buffer

	w, err := NewWriter("csv", &buf)
	if err != nil {
		t.Fatalf("NewWriter(csv) error: %v", err)
	}

	if err := w.WriteHeader(); err != nil {
		t.Fatalf("WriteHeader() error: %v", err)
	}

	if err := w.WriteResult(checker.DomainResult{Domain: "example.com", HasMX: true, HasSPF: true}); err != nil {
		t.Fatalf("WriteResult() error: %v", err)
	}

	if err := w.Flush(); err != nil {
		t.Fatalf("Flush() error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "domain,hasMX,hasSPF,spfRecord,hasDMARC,dmarcRecord,hasBIMI,bimiRecord,hasMTASTS,mtaSTSRecord,hasTLSRPT,tlsRPTRecord,scoreTotal") {
		t.Fatalf("missing CSV header in output: %q", out)
	}
	if !strings.Contains(out, "example.com,true,true") {
		t.Fatalf("missing CSV row in output: %q", out)
	}
}

func TestNewWriterJSON(t *testing.T) {
	var buf bytes.Buffer

	w, err := NewWriter("json", &buf)
	if err != nil {
		t.Fatalf("NewWriter(json) error: %v", err)
	}

	if err := w.WriteHeader(); err != nil {
		t.Fatalf("WriteHeader() error: %v", err)
	}

	if err := w.WriteResult(checker.DomainResult{Domain: "example.com", HasDMARC: true, DMARCRecord: "v=DMARC1; p=none"}); err != nil {
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

func TestNewWriterInvalidFormat(t *testing.T) {
	_, err := NewWriter("xml", &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}
