package checker

import "testing"

func TestNewNetDNSResolverWithServerValidation(t *testing.T) {
	_, err := NewNetDNSResolverWithServer("", "udp")
	if err == nil {
		t.Fatal("expected error for empty resolver address")
	}

	_, err = NewNetDNSResolverWithServer("1.1.1.1", "udp")
	if err == nil {
		t.Fatal("expected error for missing port")
	}

	_, err = NewNetDNSResolverWithServer("1.1.1.1:53", "icmp")
	if err == nil {
		t.Fatal("expected error for unsupported protocol")
	}

	resolver, err := NewNetDNSResolverWithServer("1.1.1.1:53", "udp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolver == nil {
		t.Fatal("expected non-nil resolver")
	}
}
