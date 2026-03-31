package checker

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"email-checker-tool/internal/lint"
)

type Service struct {
	workers       int
	timeout       time.Duration
	dns           DNSResolver
	enableDKIM    bool
	dkimSelectors []string
	enableLint    bool
	enableScore   bool
}

type job struct {
	index  int
	domain string
}

func NewService(cfg Config) (*Service, error) {
	if cfg.Workers <= 0 {
		return nil, fmt.Errorf("workers must be greater than zero")
	}
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("timeout must be greater than zero")
	}
	if cfg.DNS == nil {
		return nil, fmt.Errorf("dns resolver is required")
	}

	selectors := normalizeSelectors(cfg.DKIMSelectors)
	if cfg.EnableDKIM && len(selectors) == 0 {
		selectors = []string{"default", "selector1", "selector2", "google"}
	}

	return &Service{
		workers:       cfg.Workers,
		timeout:       cfg.Timeout,
		dns:           cfg.DNS,
		enableDKIM:    cfg.EnableDKIM,
		dkimSelectors: selectors,
		enableLint:    cfg.EnableLint,
		enableScore:   cfg.EnableScore,
	}, nil
}

func (s *Service) CheckDomains(domains []string) []CheckResult {
	if len(domains) == 0 {
		return nil
	}

	jobs := make(chan job)
	results := make(chan CheckResult, len(domains))
	var wg sync.WaitGroup

	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				result, err := s.checkDomain(j.domain)
				results <- CheckResult{
					Index:        j.index,
					DomainResult: result,
					Err:          err,
				}
			}
		}()
	}

	for i, domain := range domains {
		jobs <- job{index: i, domain: domain}
	}
	close(jobs)

	wg.Wait()
	close(results)

	ordered := make([]CheckResult, len(domains))
	for result := range results {
		ordered[result.Index] = result
	}

	return ordered
}

func (s *Service) checkDomain(domain string) (DomainResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	result := DomainResult{Domain: domain}
	var errs []string

	mxRecords, err := s.dns.LookupMX(ctx, domain)
	if err != nil {
		errs = append(errs, fmt.Sprintf("mx: %v", err))
	}
	if len(mxRecords) > 0 {
		result.HasMX = true
	}

	txtRecords, err := s.dns.LookupTXT(ctx, domain)
	if err != nil {
		errs = append(errs, fmt.Sprintf("spf: %v", err))
	}
	spfCount := countRecordsByPrefix(txtRecords, "v=spf1")
	if spfRecord, ok := findRecordByPrefix(txtRecords, "v=spf1"); ok {
		result.HasSPF = true
		result.SPFRecord = spfRecord
	}

	dmarcRecords, err := s.dns.LookupTXT(ctx, "_dmarc."+domain)
	if err != nil {
		errs = append(errs, fmt.Sprintf("dmarc: %v", err))
	}
	if dmarcRecord, ok := findRecordByPrefix(dmarcRecords, "v=DMARC1"); ok {
		result.HasDMARC = true
		result.DMARCRecord = dmarcRecord
	}

	bimiRecords, err := s.dns.LookupTXT(ctx, "default._bimi."+domain)
	if err == nil {
		if bimiRecord, ok := findRecordByPrefix(bimiRecords, "v=BIMI1"); ok {
			result.HasBIMI = true
			result.BIMIRecord = bimiRecord
		}
	}

	mtaSTSRecords, err := s.dns.LookupTXT(ctx, "_mta-sts."+domain)
	if err == nil {
		if mtaSTSRecord, ok := findRecordByPrefix(mtaSTSRecords, "v=STSv1"); ok {
			result.HasMTASTS = true
			result.MTASTSRecord = mtaSTSRecord
		}
	}

	tlsRPTRecords, err := s.dns.LookupTXT(ctx, "_smtp._tls."+domain)
	if err == nil {
		if tlsRPTRecord, ok := findRecordByPrefix(tlsRPTRecords, "v=TLSRPTv1"); ok {
			result.HasTLSRPT = true
			result.TLSRPTRecord = tlsRPTRecord
		}
	}

	if s.enableDKIM {
		result.DKIM = s.checkDKIM(ctx, domain)
	}

	var lintFindings []lint.Finding
	if s.enableLint || s.enableScore {
		lintFindings = lint.Evaluate(lint.Signals{
			HasMX:          result.HasMX,
			HasSPF:         result.HasSPF,
			SPFRecord:      result.SPFRecord,
			SPFRecordCount: spfCount,
			HasDMARC:       result.HasDMARC,
			DMARCRecord:    result.DMARCRecord,
			HasAnyDKIM:     hasAnyDKIM(result.DKIM),
			HasBIMI:        result.HasBIMI,
			HasMTASTS:      result.HasMTASTS,
			HasTLSRPT:      result.HasTLSRPT,
		})
	}

	if s.enableLint {
		result.Findings = toCheckerFindings(lintFindings)
	}

	if s.enableScore {
		temp := result
		temp.Findings = toCheckerFindings(lintFindings)
		score := calculateScore(temp)
		result.Score = &score
	}

	if len(errs) > 0 {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			errs = append(errs, "timeout exceeded")
		}
		return result, errors.New(strings.Join(errs, "; "))
	}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return result, fmt.Errorf("timeout exceeded")
	}

	return result, nil
}

func (s *Service) checkDKIM(ctx context.Context, domain string) []DKIMCheck {
	checks := make([]DKIMCheck, 0, len(s.dkimSelectors))
	for _, selector := range s.dkimSelectors {
		name := selector + "._domainkey." + domain
		txtRecords, err := s.dns.LookupTXT(ctx, name)
		if err != nil {
			checks = append(checks, DKIMCheck{Selector: selector, Error: err.Error()})
			continue
		}

		record, ok := findRecordByPrefix(txtRecords, "v=DKIM1")
		if !ok {
			checks = append(checks, DKIMCheck{Selector: selector, Found: false})
			continue
		}

		checks = append(checks, DKIMCheck{Selector: selector, Found: true, Record: record})
	}

	return checks
}

func normalizeSelectors(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(raw))
	selectors := make([]string, 0, len(raw))
	for _, selector := range raw {
		normalized := strings.ToLower(strings.TrimSpace(selector))
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		selectors = append(selectors, normalized)
	}

	sort.Strings(selectors)
	return selectors
}

func calculateScore(result DomainResult) ScoreBreakdown {
	auth := 0
	if result.HasMX {
		auth += 10
	}
	if result.HasSPF {
		auth += 15
	}
	if result.HasDMARC {
		auth += 15
	}
	if result.HasBIMI {
		auth += 5
	}
	if hasAnyDKIM(result.DKIM) {
		auth += 20
	}

	policy := 20
	reporting := 20

	if result.HasMTASTS {
		reporting += 6
	}
	if result.HasTLSRPT {
		reporting += 4
	}

	for _, finding := range result.Findings {
		switch finding.Severity {
		case SeverityError:
			policy -= 8
			reporting -= 4
		case SeverityWarn:
			policy -= 4
			reporting -= 2
		}
	}

	if policy < 0 {
		policy = 0
	}
	if reporting < 0 {
		reporting = 0
	}

	total := auth + policy + reporting
	if total > 100 {
		total = 100
	}

	return ScoreBreakdown{
		Total:          total,
		Authentication: auth,
		Policy:         policy,
		Reporting:      reporting,
	}
}

func hasAnyDKIM(checks []DKIMCheck) bool {
	for _, check := range checks {
		if check.Found {
			return true
		}
	}
	return false
}

func ResultHasFailure(result CheckResult) bool {
	if result.Err != nil {
		return true
	}
	for _, finding := range result.Findings {
		if finding.Severity == SeverityWarn || finding.Severity == SeverityError {
			return true
		}
	}
	return false
}

func toCheckerFindings(items []lint.Finding) []Finding {
	if len(items) == 0 {
		return nil
	}

	findings := make([]Finding, 0, len(items))
	for _, item := range items {
		findings = append(findings, Finding{
			Code:     item.Code,
			Severity: item.Severity,
			Message:  item.Message,
			Hint:     item.Hint,
		})
	}

	return findings
}

func findRecordByPrefix(records []string, prefix string) (string, bool) {
	normalizedPrefix := strings.ToLower(prefix)
	for _, record := range records {
		trimmedRecord := strings.TrimSpace(record)
		if strings.HasPrefix(strings.ToLower(trimmedRecord), normalizedPrefix) {
			return trimmedRecord, true
		}
	}

	return "", false
}

func countRecordsByPrefix(records []string, prefix string) int {
	normalizedPrefix := strings.ToLower(prefix)
	count := 0
	for _, record := range records {
		trimmedRecord := strings.TrimSpace(record)
		if strings.HasPrefix(strings.ToLower(trimmedRecord), normalizedPrefix) {
			count++
		}
	}
	return count
}
