package lint

import "testing"

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name      string
		signals   Signals
		wantCodes []string
	}{
		{
			name: "missing records",
			signals: Signals{
				HasMX:      false,
				HasSPF:     false,
				HasDMARC:   false,
				HasAnyDKIM: false,
			},
			wantCodes: []string{"MX_MISSING", "SPF_MISSING", "DMARC_MISSING", "DKIM_NOT_FOUND", "BIMI_MISSING", "MTA_STS_MISSING", "TLS_RPT_MISSING"},
		},
		{
			name: "weak but present policies",
			signals: Signals{
				HasMX:          true,
				HasSPF:         true,
				SPFRecord:      "v=spf1 include:_spf.example.com ~all",
				SPFRecordCount: 1,
				HasDMARC:       true,
				DMARCRecord:    "v=DMARC1; p=none",
				HasAnyDKIM:     true,
				HasBIMI:        true,
				HasMTASTS:      true,
				HasTLSRPT:      true,
			},
			wantCodes: []string{"SPF_SOFTFAIL", "DMARC_POLICY_NONE", "DMARC_RUA_MISSING", "DMARC_RUF_MISSING"},
		},
		{
			name: "advanced gaps",
			signals: Signals{
				HasMX:          true,
				HasSPF:         true,
				SPFRecord:      "v=spf1 ptr include:_spf.example.com",
				SPFRecordCount: 2,
				HasDMARC:       true,
				DMARCRecord:    "v=DMARC1; p=none; pct=50",
			},
			wantCodes: []string{"SPF_MULTIPLE_RECORDS", "SPF_PTR_USAGE", "SPF_NO_TERMINAL", "DMARC_PCT_LOW", "BIMI_MISSING", "MTA_STS_MISSING", "TLS_RPT_MISSING"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(tt.signals)
			for _, want := range tt.wantCodes {
				if !containsCode(got, want) {
					t.Fatalf("expected finding code %q in %+v", want, got)
				}
			}
		})
	}
}

func TestParseDMARCPct(t *testing.T) {
	pct, ok := parseDMARCPct("v=DMARC1; p=none; pct=90")
	if !ok || pct != 90 {
		t.Fatalf("parseDMARCPct() = (%d, %t), want (90, true)", pct, ok)
	}

	_, ok = parseDMARCPct("v=DMARC1; p=none; pct=abc")
	if ok {
		t.Fatal("expected invalid pct parse")
	}
}

func containsCode(items []Finding, code string) bool {
	for _, item := range items {
		if item.Code == code {
			return true
		}
	}
	return false
}
