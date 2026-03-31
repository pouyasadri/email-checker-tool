package lint

import "strings"

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
	HasMX       bool
	HasSPF      bool
	SPFRecord   string
	HasDMARC    bool
	DMARCRecord string
	HasAnyDKIM  bool
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
	}

	if !signals.HasAnyDKIM {
		findings = append(findings, Finding{
			Code:     "DKIM_NOT_FOUND",
			Severity: SeverityWarn,
			Message:  "no DKIM selector found",
			Hint:     "enable DKIM and publish at least one selector",
		})
	}

	return findings
}
