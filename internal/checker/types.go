package checker

import "time"

const (
	SeverityInfo  = "info"
	SeverityWarn  = "warn"
	SeverityError = "error"
)

type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Hint     string `json:"hint,omitempty"`
}

type DKIMCheck struct {
	Selector string `json:"selector"`
	Found    bool   `json:"found"`
	Record   string `json:"record,omitempty"`
	Error    string `json:"error,omitempty"`
}

type ScoreBreakdown struct {
	Total          int `json:"total"`
	Authentication int `json:"authentication"`
	Policy         int `json:"policy"`
	Reporting      int `json:"reporting"`
}

type DomainResult struct {
	Domain       string          `json:"domain"`
	HasMX        bool            `json:"hasMX"`
	HasSPF       bool            `json:"hasSPF"`
	SPFRecord    string          `json:"spfRecord,omitempty"`
	HasDMARC     bool            `json:"hasDMARC"`
	DMARCRecord  string          `json:"dmarcRecord,omitempty"`
	HasBIMI      bool            `json:"hasBIMI"`
	BIMIRecord   string          `json:"bimiRecord,omitempty"`
	HasMTASTS    bool            `json:"hasMTASTS"`
	MTASTSRecord string          `json:"mtaSTSRecord,omitempty"`
	HasTLSRPT    bool            `json:"hasTLSRPT"`
	TLSRPTRecord string          `json:"tlsRPTRecord,omitempty"`
	DKIM         []DKIMCheck     `json:"dkim,omitempty"`
	Findings     []Finding       `json:"findings,omitempty"`
	Score        *ScoreBreakdown `json:"score,omitempty"`
}

type CheckResult struct {
	Index int
	DomainResult
	Err error
}

type Config struct {
	Workers       int
	Timeout       time.Duration
	DNS           DNSResolver
	EnableDKIM    bool
	DKIMSelectors []string
	EnableLint    bool
	EnableScore   bool
}
