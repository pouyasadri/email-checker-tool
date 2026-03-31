package report

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"email-checker-tool/internal/checker"
)

func TestBuildSummary(t *testing.T) {
	results := []checker.CheckResult{
		{
			DomainResult: checker.DomainResult{Domain: "a.com", HasMX: true, HasSPF: true, HasDMARC: true},
		},
		{
			DomainResult: checker.DomainResult{
				Domain:   "b.com",
				Findings: []checker.Finding{{Code: "SPF_MISSING", Severity: checker.SeverityError, Message: "missing"}},
			},
			Err: errors.New("dns error"),
		},
	}

	s := BuildSummary(results)
	if s.Total != 2 {
		t.Fatalf("Total = %d, want 2", s.Total)
	}
	if s.LookupErrors != 1 {
		t.Fatalf("LookupErrors = %d, want 1", s.LookupErrors)
	}
	if s.Failures != 1 {
		t.Fatalf("Failures = %d, want 1", s.Failures)
	}
}

func TestFilterFailuresOnly(t *testing.T) {
	results := []checker.CheckResult{
		{DomainResult: checker.DomainResult{Domain: "ok.com"}},
		{DomainResult: checker.DomainResult{Domain: "warn.com", Findings: []checker.Finding{{Code: "X", Severity: checker.SeverityWarn}}}},
	}

	filtered := FilterFailuresOnly(results)
	if len(filtered) != 1 {
		t.Fatalf("len(filtered) = %d, want 1", len(filtered))
	}
	if filtered[0].Domain != "warn.com" {
		t.Fatalf("filtered[0].Domain = %q, want warn.com", filtered[0].Domain)
	}
}

func TestWriteSummaryJSON(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSummary(&buf, SummaryFormatJSON, Summary{Total: 3, Failures: 1})
	if err != nil {
		t.Fatalf("WriteSummary() error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"total":3`) {
		t.Fatalf("expected total in output: %q", out)
	}
}

func TestWriteJSONReport(t *testing.T) {
	var buf bytes.Buffer
	err := WriteJSONReport(&buf, []checker.CheckResult{{DomainResult: checker.DomainResult{Domain: "example.com"}}})
	if err != nil {
		t.Fatalf("WriteJSONReport() error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"version": "v1"`) {
		t.Fatalf("expected report version in output: %q", out)
	}
}

func TestWriteSARIFReport(t *testing.T) {
	var buf bytes.Buffer
	results := []checker.CheckResult{
		{DomainResult: checker.DomainResult{Domain: "example.com", Findings: []checker.Finding{{Code: "SPF_MISSING", Severity: checker.SeverityError, Message: "missing SPF"}}}},
	}

	err := WriteSARIFReport(&buf, results)
	if err != nil {
		t.Fatalf("WriteSARIFReport() error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"version": "2.1.0"`) {
		t.Fatalf("expected SARIF version in output: %q", out)
	}
	if !strings.Contains(out, `"ruleId": "SPF_MISSING"`) {
		t.Fatalf("expected SARIF rule in output: %q", out)
	}
}
