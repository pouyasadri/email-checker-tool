package lint

import (
	"strconv"
	"strings"
)

const (
	SeverityInfo  = "info"
	SeverityWarn  = "warn"
	SeverityError = "error"
)

type Finding struct {
	Code     string
	Severity string
	Message  string
	Hint     string
}

type Signals struct {
	HasMX          bool
	HasSPF         bool
	SPFRecord      string
	SPFRecordCount int
	HasDMARC       bool
	DMARCRecord    string
	HasAnyDKIM     bool
	HasBIMI        bool
	HasMTASTS      bool
	HasTLSRPT      bool
}

func Evaluate(signals Signals) []Finding {
	findings := make([]Finding, 0)

	if !signals.HasMX {
		findings = append(findings, Finding{
			Code:     "MX_MISSING",
			Severity: SeverityWarn,
			Message:  "domain has no MX records",
			Hint:     "configure at least one mail exchanger",
		})
	}

	if !signals.HasSPF {
		findings = append(findings, Finding{
			Code:     "SPF_MISSING",
			Severity: SeverityError,
			Message:  "SPF record not found",
			Hint:     "publish SPF record like v=spf1 ... -all",
		})
	} else {
		spf := strings.ToLower(strings.TrimSpace(signals.SPFRecord))
		if signals.SPFRecordCount > 1 {
			findings = append(findings, Finding{
				Code:     "SPF_MULTIPLE_RECORDS",
				Severity: SeverityError,
				Message:  "multiple SPF records detected",
				Hint:     "merge SPF policy into a single TXT record",
			})
		}
		switch {
		case strings.Contains(spf, "+all"):
			findings = append(findings, Finding{
				Code:     "SPF_PLUS_ALL",
				Severity: SeverityError,
				Message:  "SPF record contains +all",
				Hint:     "replace +all with -all or ~all",
			})
		case strings.Contains(spf, "~all"):
			findings = append(findings, Finding{
				Code:     "SPF_SOFTFAIL",
				Severity: SeverityWarn,
				Message:  "SPF record ends with softfail (~all)",
				Hint:     "move to -all when policy is stable",
			})
		case !strings.Contains(spf, "-all"):
			findings = append(findings, Finding{
				Code:     "SPF_NO_TERMINAL",
				Severity: SeverityWarn,
				Message:  "SPF record has no terminal all mechanism",
				Hint:     "add -all or ~all at the end of SPF policy",
			})
		}
		if strings.Contains(spf, " ptr") {
			findings = append(findings, Finding{
				Code:     "SPF_PTR_USAGE",
				Severity: SeverityWarn,
				Message:  "SPF record uses ptr mechanism",
				Hint:     "replace ptr with explicit ip4/ip6/include mechanisms",
			})
		}
	}

	if !signals.HasDMARC {
		findings = append(findings, Finding{
			Code:     "DMARC_MISSING",
			Severity: SeverityError,
			Message:  "DMARC record not found",
			Hint:     "publish DMARC record like v=DMARC1; p=quarantine",
		})
	} else {
		dmarc := strings.ToLower(strings.TrimSpace(signals.DMARCRecord))
		if !strings.Contains(dmarc, "p=") {
			findings = append(findings, Finding{
				Code:     "DMARC_POLICY_MISSING",
				Severity: SeverityError,
				Message:  "DMARC policy tag p= is missing",
				Hint:     "set p=none, p=quarantine, or p=reject",
			})
		}
		if strings.Contains(dmarc, "p=none") {
			findings = append(findings, Finding{
				Code:     "DMARC_POLICY_NONE",
				Severity: SeverityWarn,
				Message:  "DMARC policy is p=none",
				Hint:     "enforce with p=quarantine or p=reject",
			})
		}
		if !strings.Contains(dmarc, "rua=") {
			findings = append(findings, Finding{
				Code:     "DMARC_RUA_MISSING",
				Severity: SeverityWarn,
				Message:  "DMARC aggregate report address (rua) missing",
				Hint:     "add rua=mailto:... to improve monitoring",
			})
		}
		if !strings.Contains(dmarc, "ruf=") {
			findings = append(findings, Finding{
				Code:     "DMARC_RUF_MISSING",
				Severity: SeverityInfo,
				Message:  "DMARC forensic report address (ruf) missing",
				Hint:     "add ruf=mailto:... if forensic reporting is desired",
			})
		}
		if pct, ok := parseDMARCPct(dmarc); ok && pct < 100 {
			findings = append(findings, Finding{
				Code:     "DMARC_PCT_LOW",
				Severity: SeverityWarn,
				Message:  "DMARC pct is below 100",
				Hint:     "increase pct to 100 once rollout confidence is high",
			})
		}
	}

	if !signals.HasAnyDKIM {
		findings = append(findings, Finding{
			Code:     "DKIM_NOT_FOUND",
			Severity: SeverityWarn,
			Message:  "no DKIM selector found",
			Hint:     "enable DKIM and publish at least one selector",
		})
	}

	if !signals.HasBIMI {
		findings = append(findings, Finding{
			Code:     "BIMI_MISSING",
			Severity: SeverityInfo,
			Message:  "BIMI record not found",
			Hint:     "publish default._bimi TXT record if brand indicators are needed",
		})
	}

	if !signals.HasMTASTS {
		findings = append(findings, Finding{
			Code:     "MTA_STS_MISSING",
			Severity: SeverityWarn,
			Message:  "MTA-STS TXT record not found",
			Hint:     "publish _mta-sts TXT record and corresponding policy host",
		})
	}

	if !signals.HasTLSRPT {
		findings = append(findings, Finding{
			Code:     "TLS_RPT_MISSING",
			Severity: SeverityInfo,
			Message:  "TLS-RPT TXT record not found",
			Hint:     "publish _smtp._tls TXT record with rua destination",
		})
	}

	return findings
}

func parseDMARCPct(record string) (int, bool) {
	parts := strings.Split(record, ";")
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if !strings.HasPrefix(trimmed, "pct=") {
			continue
		}
		value := strings.TrimPrefix(trimmed, "pct=")
		pct, err := strconv.Atoi(value)
		if err != nil || pct < 0 || pct > 100 {
			return 0, false
		}
		return pct, true
	}

	return 0, false
}
