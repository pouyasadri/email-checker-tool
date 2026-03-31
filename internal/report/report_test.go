package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"email-checker-tool/internal/checker"
)

func TestBuildSummary(t *testing.T) {
	results := []checker.CheckResult{
		{
			DomainResult: checker.DomainResult{Domain: "a.com", HasMX: true, HasSPF: true, HasDMARC: true, HasBIMI: true, HasMTASTS: true, HasTLSRPT: true},
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
	if s.BIMIPresent != 1 || s.MTASTSPresent != 1 || s.TLSRPTPresent != 1 {
		t.Fatalf("unexpected advanced counters: %+v", s)
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

func TestWriteJSONReportGolden(t *testing.T) {
	results := goldenResultsFixture()

	var buf bytes.Buffer
	if err := WriteJSONReport(&buf, results); err != nil {
		t.Fatalf("WriteJSONReport() error: %v", err)
	}

	goldenPath := filepath.Join("testdata", "report_v1.golden.json")
	goldenRaw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden file error: %v", err)
	}

	if !jsonEquivalent(buf.Bytes(), goldenRaw) {
		t.Fatalf("json report does not match golden file %s", goldenPath)
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

func TestWriteSARIFReportGolden(t *testing.T) {
	results := goldenResultsFixture()

	var buf bytes.Buffer
	if err := WriteSARIFReport(&buf, results); err != nil {
		t.Fatalf("WriteSARIFReport() error: %v", err)
	}

	goldenPath := filepath.Join("testdata", "report_v1.golden.sarif")
	goldenRaw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden file error: %v", err)
	}

	if !jsonEquivalent(buf.Bytes(), goldenRaw) {
		t.Fatalf("sarif report does not match golden file %s", goldenPath)
	}
}

func goldenResultsFixture() []checker.CheckResult {
	return []checker.CheckResult{
		{
			Index: 0,
			DomainResult: checker.DomainResult{
				Domain:       "secure.example",
				HasMX:        true,
				HasSPF:       true,
				SPFRecord:    "v=spf1 -all",
				HasDMARC:     true,
				DMARCRecord:  "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
				HasBIMI:      true,
				BIMIRecord:   "v=BIMI1; l=https://example.com/logo.svg",
				HasMTASTS:    true,
				MTASTSRecord: "v=STSv1; id=20260331",
				HasTLSRPT:    true,
				TLSRPTRecord: "v=TLSRPTv1; rua=mailto:tls@example.com",
				DKIM: []checker.DKIMCheck{
					{Selector: "default", Found: true, Record: "v=DKIM1; p=abc"},
				},
			},
		},
		{
			Index: 1,
			DomainResult: checker.DomainResult{
				Domain:    "weak.example",
				HasMX:     true,
				Findings:  []checker.Finding{{Code: "SPF_MISSING", Severity: checker.SeverityError, Message: "SPF record not found"}},
				HasSPF:    false,
				HasDMARC:  false,
				HasBIMI:   false,
				HasMTASTS: false,
				HasTLSRPT: false,
			},
			Err: errors.New("spf lookup failed"),
		},
	}
}

func jsonEquivalent(a []byte, b []byte) bool {
	var left any
	if err := json.Unmarshal(a, &left); err != nil {
		return false
	}
	var right any
	if err := json.Unmarshal(b, &right); err != nil {
		return false
	}

	leftNorm, err := json.Marshal(left)
	if err != nil {
		return false
	}
	rightNorm, err := json.Marshal(right)
	if err != nil {
		return false
	}

	return bytes.Equal(leftNorm, rightNorm)
}
