package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSelectors(t *testing.T) {
	got := parseSelectors(" default, selector1 ,,google ")
	if len(got) != 3 {
		t.Fatalf("len(got) = %d, want 3", len(got))
	}
	if got[0] != "default" || got[1] != "selector1" || got[2] != "google" {
		t.Fatalf("unexpected selectors: %#v", got)
	}
}

func TestWriteReportInvalidFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.out")
	err := writeReport(path, "xml", nil)
	if err == nil {
		t.Fatal("expected unsupported format error")
	}
	if !strings.Contains(err.Error(), "unsupported report format") {
		t.Fatalf("unexpected error: %v", err)
	}
}
