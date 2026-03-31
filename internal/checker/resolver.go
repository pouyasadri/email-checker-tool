package checker

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

type DNSResolver interface {
	LookupMX(ctx context.Context, domain string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, domain string) ([]string, error)
}

type netDNSResolver struct {
	resolver *net.Resolver
}

func NewNetDNSResolver() DNSResolver {
	return &netDNSResolver{resolver: net.DefaultResolver}
}

func NewNetDNSResolverWithServer(serverAddr string, proto string) (DNSResolver, error) {
	serverAddr = strings.TrimSpace(serverAddr)
	if serverAddr == "" {
		return nil, fmt.Errorf("resolver address cannot be empty")
	}
	if _, _, err := net.SplitHostPort(serverAddr); err != nil {
		return nil, fmt.Errorf("invalid resolver address %q: %w", serverAddr, err)
	}

	proto = strings.ToLower(strings.TrimSpace(proto))
	if proto != "udp" && proto != "tcp" {
		return nil, fmt.Errorf("unsupported resolver protocol %q (use udp or tcp)", proto)
	}

	dialer := &net.Dialer{Timeout: 2 * time.Second}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network string, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, proto, serverAddr)
		},
	}

	return &netDNSResolver{resolver: resolver}, nil
}

func (r *netDNSResolver) LookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	return r.resolver.LookupMX(ctx, domain)
}

func (r *netDNSResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	return r.resolver.LookupTXT(ctx, domain)
}
