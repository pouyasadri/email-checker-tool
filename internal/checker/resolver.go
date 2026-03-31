package checker

import (
	"context"
	"net"
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

func (r *netDNSResolver) LookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	return r.resolver.LookupMX(ctx, domain)
}

func (r *netDNSResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	return r.resolver.LookupTXT(ctx, domain)
}
