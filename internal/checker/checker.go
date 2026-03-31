package checker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

type Service struct {
	workers int
	timeout time.Duration
	dns     DNSResolver
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

	return &Service{
		workers: cfg.Workers,
		timeout: cfg.Timeout,
		dns:     cfg.DNS,
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
