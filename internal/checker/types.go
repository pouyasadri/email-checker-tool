package checker

import "time"

type DomainResult struct {
	Domain      string `json:"domain"`
	HasMX       bool   `json:"hasMX"`
	HasSPF      bool   `json:"hasSPF"`
	SPFRecord   string `json:"spfRecord,omitempty"`
	HasDMARC    bool   `json:"hasDMARC"`
	DMARCRecord string `json:"dmarcRecord,omitempty"`
}

type CheckResult struct {
	Index int
	DomainResult
	Err error
}

type Config struct {
	Workers int
	Timeout time.Duration
	DNS     DNSResolver
}
