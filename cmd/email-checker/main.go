package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"email-checker-tool/internal/checker"
	"email-checker-tool/internal/input"
	"email-checker-tool/internal/output"
	"email-checker-tool/internal/report"
)

const (
	defaultTimeout = 3 * time.Second
)

func main() {
	format := flag.String("format", output.FormatCSV, "Output format: csv or json")
	workers := flag.Int("workers", runtime.NumCPU(), "Number of concurrent workers")
	timeout := flag.Duration("timeout", defaultTimeout, "Per-domain check timeout (e.g. 2s, 500ms)")
	resolverAddr := flag.String("resolver", "", "Custom DNS resolver address (host:port), e.g. 1.1.1.1:53")
	resolverProto := flag.String("resolver-proto", "udp", "Resolver protocol: udp or tcp")
	enableDKIM := flag.Bool("check-dkim", false, "Enable DKIM selector checks")
	dkimSelectorsRaw := flag.String("dkim-selectors", "", "Comma-separated DKIM selectors (default: common selectors)")
	enableLint := flag.Bool("lint", false, "Enable SPF/DMARC lint findings")
	enableScore := flag.Bool("score", false, "Enable weighted security scoring")
	summary := flag.Bool("summary", false, "Print summary metrics to stderr")
	summaryFormat := flag.String("summary-format", report.SummaryFormatText, "Summary format: text or json")
	failuresOnly := flag.Bool("failures-only", false, "Only emit failed domains")
	reportPath := flag.String("report-file", "", "Optional report output file path")
	reportFormat := flag.String("report-format", report.SummaryFormatJSON, "Report format: json or sarif")
	flag.Parse()

	domains, err := input.ReadDomains(os.Stdin)
	if err != nil {
		log.Fatalf("error: could not read domains: %v", err)
	}

	writer, err := output.NewWriter(*format, os.Stdout)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	if err := writer.WriteHeader(); err != nil {
		log.Fatalf("error: could not write output header: %v", err)
	}

	resolver, err := newResolver(*resolverAddr, *resolverProto)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	service, err := checker.NewService(checker.Config{
		Workers:       *workers,
		Timeout:       *timeout,
		DNS:           resolver,
		EnableDKIM:    *enableDKIM,
		DKIMSelectors: parseSelectors(*dkimSelectorsRaw),
		EnableLint:    *enableLint,
		EnableScore:   *enableScore,
	})
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	results := service.CheckDomains(domains)
	if *failuresOnly {
		results = report.FilterFailuresOnly(results)
	}

	for _, result := range results {
		if result.Err != nil {
			log.Printf("warning: could not fully check %q: %v", result.Domain, result.Err)
		}

		if err := writer.WriteResult(result.DomainResult); err != nil {
			log.Fatalf("error: could not write output row: %v", err)
		}
	}

	if err := writer.Flush(); err != nil {
		log.Fatalf("error: could not flush output: %v", err)
	}

	if *summary {
		s := report.BuildSummary(results)
		if err := report.WriteSummary(os.Stderr, *summaryFormat, s); err != nil {
			log.Fatalf("error: could not write summary: %v", err)
		}
	}

	if *reportPath != "" {
		if err := writeReport(*reportPath, *reportFormat, results); err != nil {
			log.Fatalf("error: could not write report: %v", err)
		}
	}
}

func parseSelectors(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	selectors := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			selectors = append(selectors, trimmed)
		}
	}
	return selectors
}

func newResolver(addr string, proto string) (checker.DNSResolver, error) {
	if strings.TrimSpace(addr) == "" {
		return checker.NewNetDNSResolver(), nil
	}
	return checker.NewNetDNSResolverWithServer(addr, proto)
}

func writeReport(path string, format string, results []checker.CheckResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	switch strings.ToLower(strings.TrimSpace(format)) {
	case report.SummaryFormatJSON:
		return report.WriteJSONReport(f, results)
	case report.SummaryFormatSARIF:
		return report.WriteSARIFReport(f, results)
	default:
		return fmt.Errorf("unsupported report format %q (use json or sarif)", format)
	}
}
