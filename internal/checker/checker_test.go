package checker

import (
	"context"
	"errors"
	"net"
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
