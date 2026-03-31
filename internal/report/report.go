package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"email-checker-tool/internal/checker"
)

const (
	SummaryFormatText  = "text"
	SummaryFormatJSON  = "json"
	SummaryFormatSARIF = "sarif"
)

type Summary struct {
	Total          int `json:"total"`
	LookupErrors   int `json:"lookupErrors"`
	Failures       int `json:"failures"`
	MXPresent      int `json:"mxPresent"`
	SPFPresent     int `json:"spfPresent"`
	DMARCPresent   int `json:"dmarcPresent"`
	DKIMAnyPresent int `json:"dkimAnyPresent"`
}

func BuildSummary(results []checker.CheckResult) Summary {
	s := Summary{Total: len(results)}
	for _, result := range results {
		if result.Err != nil {
			s.LookupErrors++
		}
		if checker.ResultHasFailure(result) {
			s.Failures++
		}
		if result.HasMX {
			s.MXPresent++
		}
		if result.HasSPF {
			s.SPFPresent++
		}
		if result.HasDMARC {
			s.DMARCPresent++
		}
		for _, dkim := range result.DKIM {
			if dkim.Found {
				s.DKIMAnyPresent++
				break
			}
		}
	}
	return s
}

func FilterFailuresOnly(results []checker.CheckResult) []checker.CheckResult {
	filtered := make([]checker.CheckResult, 0)
	for _, result := range results {
		if checker.ResultHasFailure(result) {
			filtered = append(filtered, result)
		}
	}
	return filtered
}

func WriteSummary(w io.Writer, format string, summary Summary) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case SummaryFormatText:
		_, err := fmt.Fprintf(
			w,
			"total=%d failures=%d lookupErrors=%d mxPresent=%d spfPresent=%d dmarcPresent=%d dkimAnyPresent=%d\n",
			summary.Total,
			summary.Failures,
			summary.LookupErrors,
			summary.MXPresent,
			summary.SPFPresent,
			summary.DMARCPresent,
			summary.DKIMAnyPresent,
		)
		return err
	case SummaryFormatJSON:
		enc := json.NewEncoder(w)
		return enc.Encode(summary)
	default:
		return fmt.Errorf("unsupported summary format %q", format)
	}
}

type JSONReport struct {
	Version string                `json:"version"`
	Summary Summary               `json:"summary"`
	Results []checker.CheckResult `json:"results"`
}

func WriteJSONReport(w io.Writer, results []checker.CheckResult) error {
	report := JSONReport{
		Version: "v1",
		Summary: BuildSummary(results),
		Results: results,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func WriteSARIFReport(w io.Writer, results []checker.CheckResult) error {
	type location struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []location `json:"locations,omitempty"`
	}

	sarifResults := make([]sarifResult, 0)
	for _, result := range results {
		for _, finding := range result.Findings {
			r := sarifResult{RuleID: finding.Code, Level: toSARIFLevel(finding.Severity)}
			r.Message.Text = finding.Message
			loc := location{}
			loc.PhysicalLocation.ArtifactLocation.URI = result.Domain
			r.Locations = []location{loc}
			sarifResults = append(sarifResults, r)
		}
	}

	payload := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []any{
			map[string]any{
				"tool": map[string]any{
					"driver": map[string]any{
						"name": "email-checker-tool",
					},
				},
				"results": sarifResults,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func toSARIFLevel(severity string) string {
	switch severity {
	case checker.SeverityError:
		return "error"
	case checker.SeverityWarn:
		return "warning"
	default:
		return "note"
	}
}
