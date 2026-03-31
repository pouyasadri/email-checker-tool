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
			wantCodes: []string{"MX_MISSING", "SPF_MISSING", "DMARC_MISSING", "DKIM_NOT_FOUND"},
		},
		{
			name: "weak but present policies",
			signals: Signals{
				HasMX:       true,
				HasSPF:      true,
				SPFRecord:   "v=spf1 include:_spf.example.com ~all",
				HasDMARC:    true,
				DMARCRecord: "v=DMARC1; p=none",
				HasAnyDKIM:  true,
			},
			wantCodes: []string{"SPF_SOFTFAIL", "DMARC_POLICY_NONE", "DMARC_RUA_MISSING"},
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

func containsCode(items []Finding, code string) bool {
	for _, item := range items {
		if item.Code == code {
			return true
		}
	}
	return false
}
