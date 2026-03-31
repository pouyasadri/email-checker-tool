package checker

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeDNSResolver struct {
	mxFn  func(ctx context.Context, domain string) ([]*net.MX, error)
	txtFn func(ctx context.Context, domain string) ([]string, error)
}

func (f fakeDNSResolver) LookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	if f.mxFn != nil {
		return f.mxFn(ctx, domain)
	}
	return nil, nil
}

func (f fakeDNSResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	if f.txtFn != nil {
		return f.txtFn(ctx, domain)
	}
	return nil, nil
}

func TestNewServiceValidation(t *testing.T) {
	_, err := NewService(Config{Workers: 0, Timeout: time.Second, DNS: fakeDNSResolver{}})
	if err == nil {
		t.Fatal("expected workers validation error")
	}

	_, err = NewService(Config{Workers: 1, Timeout: 0, DNS: fakeDNSResolver{}})
	if err == nil {
		t.Fatal("expected timeout validation error")
	}

	_, err = NewService(Config{Workers: 1, Timeout: time.Second, DNS: nil})
	if err == nil {
		t.Fatal("expected dns validation error")
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
}

func TestCheckDomainsPreservesInputOrder(t *testing.T) {
	resolver := fakeDNSResolver{
		mxFn: func(ctx context.Context, domain string) ([]*net.MX, error) {
			if domain == "slow.com" {
				time.Sleep(40 * time.Millisecond)
			}
			if domain == "fast.com" {
				time.Sleep(5 * time.Millisecond)
			}
			return []*net.MX{{Host: "mx." + domain, Pref: 10}}, nil
		},
		txtFn: func(ctx context.Context, domain string) ([]string, error) {
			switch domain {
			case "slow.com", "fast.com":
				return []string{"v=spf1 -all"}, nil
			case "_dmarc.slow.com", "_dmarc.fast.com":
				return []string{"v=DMARC1; p=none"}, nil
			default:
				return nil, nil
			}
		},
	}

	svc, err := NewService(Config{Workers: 2, Timeout: time.Second, DNS: resolver})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	results := svc.CheckDomains([]string{"slow.com", "fast.com"})
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}

	if results[0].Domain != "slow.com" || results[1].Domain != "fast.com" {
		t.Fatalf("result order not preserved: got [%s, %s]", results[0].Domain, results[1].Domain)
	}
}

func TestCheckDomainTimeoutWholeRequest(t *testing.T) {
	resolver := fakeDNSResolver{
		mxFn: func(ctx context.Context, domain string) ([]*net.MX, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		txtFn: func(ctx context.Context, domain string) ([]string, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	svc, err := NewService(Config{Workers: 1, Timeout: 20 * time.Millisecond, DNS: resolver})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	results := svc.CheckDomains([]string{"example.com"})
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}

	if results[0].Err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestCheckDomainAggregatesPartialErrors(t *testing.T) {
	errSPF := errors.New("spf lookup failed")
	resolver := fakeDNSResolver{
		mxFn: func(ctx context.Context, domain string) ([]*net.MX, error) {
			return []*net.MX{{Host: "mx.example.com", Pref: 10}}, nil
		},
		txtFn: func(ctx context.Context, domain string) ([]string, error) {
			if domain == "example.com" {
				return nil, errSPF
			}
			if domain == "_dmarc.example.com" {
				return []string{"v=DMARC1; p=reject"}, nil
			}
			return nil, nil
		},
	}

	svc, err := NewService(Config{Workers: 1, Timeout: time.Second, DNS: resolver})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	results := svc.CheckDomains([]string{"example.com"})
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}

	got := results[0]
	if !got.HasMX {
		t.Fatal("expected HasMX true")
	}
	if got.HasSPF {
		t.Fatal("expected HasSPF false")
	}
	if !got.HasDMARC {
		t.Fatal("expected HasDMARC true")
	}
	if got.Err == nil {
		t.Fatal("expected aggregated error")
	}
}

func TestCheckDomainsNoDataRaceBasic(t *testing.T) {
	var mu sync.Mutex
	seen := make(map[string]int)

	resolver := fakeDNSResolver{
		mxFn: func(ctx context.Context, domain string) ([]*net.MX, error) {
			mu.Lock()
			seen[domain]++
			mu.Unlock()
			return nil, nil
		},
		txtFn: func(ctx context.Context, domain string) ([]string, error) {
			return nil, nil
		},
	}

	svc, err := NewService(Config{Workers: 4, Timeout: time.Second, DNS: resolver})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	_ = svc.CheckDomains([]string{"a.com", "b.com", "c.com", "d.com"})

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 4 {
		t.Fatalf("expected resolver called for all domains, got %d", len(seen))
	}
}

func TestCheckDomainDKIMLintAndScore(t *testing.T) {
	resolver := fakeDNSResolver{
		mxFn: func(ctx context.Context, domain string) ([]*net.MX, error) {
			return []*net.MX{{Host: "mx.example.com", Pref: 10}}, nil
		},
		txtFn: func(ctx context.Context, domain string) ([]string, error) {
			switch domain {
			case "example.com":
				return []string{"v=spf1 include:_spf.example.com ~all"}, nil
			case "_dmarc.example.com":
				return []string{"v=DMARC1; p=none"}, nil
			case "default._bimi.example.com":
				return []string{"v=BIMI1; l=https://example.com/logo.svg"}, nil
			case "_mta-sts.example.com":
				return []string{"v=STSv1; id=20260331"}, nil
			case "_smtp._tls.example.com":
				return []string{"v=TLSRPTv1; rua=mailto:tlsrpt@example.com"}, nil
			case "default._domainkey.example.com":
				return []string{"v=DKIM1; k=rsa; p=abc"}, nil
			default:
				return nil, errors.New("not found")
			}
		},
	}

	svc, err := NewService(Config{
		Workers:       1,
		Timeout:       time.Second,
		DNS:           resolver,
		EnableDKIM:    true,
		EnableLint:    true,
		EnableScore:   true,
		DKIMSelectors: []string{"default"},
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	results := svc.CheckDomains([]string{"example.com"})
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}

	result := results[0]
	if len(result.DKIM) != 1 || !result.DKIM[0].Found {
		t.Fatalf("expected found DKIM selector, got %+v", result.DKIM)
	}
	if !result.HasBIMI || !result.HasMTASTS || !result.HasTLSRPT {
		t.Fatalf("expected BIMI/MTA-STS/TLS-RPT true, got bimi=%t mta-sts=%t tls-rpt=%t", result.HasBIMI, result.HasMTASTS, result.HasTLSRPT)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected lint findings")
	}
	if result.Score == nil || result.Score.Total <= 0 {
		t.Fatalf("expected score, got %+v", result.Score)
	}
}

func TestCountRecordsByPrefix(t *testing.T) {
	records := []string{"v=spf1 -all", "V=SPF1 include:_spf.example.com ~all", "something"}
	if got := countRecordsByPrefix(records, "v=spf1"); got != 2 {
		t.Fatalf("countRecordsByPrefix() = %d, want 2", got)
	}
}

func TestResultHasFailure(t *testing.T) {
	noFailure := CheckResult{DomainResult: DomainResult{Domain: "ok.com"}}
	if ResultHasFailure(noFailure) {
		t.Fatal("expected no failure")
	}

	withErr := CheckResult{DomainResult: DomainResult{Domain: "e.com"}, Err: errors.New("dns")}
	if !ResultHasFailure(withErr) {
		t.Fatal("expected failure from error")
	}

	withWarn := CheckResult{DomainResult: DomainResult{Domain: "w.com", Findings: []Finding{{Code: "X", Severity: SeverityWarn}}}}
	if !ResultHasFailure(withWarn) {
		t.Fatal("expected failure from warning finding")
	}
}

func TestNormalizeSelectors(t *testing.T) {
	got := normalizeSelectors([]string{"  Default ", "selector1", "default", ""})
	joined := strings.Join(got, ",")
	if joined != "default,selector1" {
		t.Fatalf("normalizeSelectors() = %q, want %q", joined, "default,selector1")
	}
}
