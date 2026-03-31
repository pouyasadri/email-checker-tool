package main

import (
	"flag"
	"log"
	"os"
	"runtime"
	"time"

	"email-checker-tool/internal/checker"
	"email-checker-tool/internal/input"
	"email-checker-tool/internal/output"
)

const (
	defaultTimeout = 3 * time.Second
)

func main() {
	format := flag.String("format", output.FormatCSV, "Output format: csv or json")
	workers := flag.Int("workers", runtime.NumCPU(), "Number of concurrent workers")
	timeout := flag.Duration("timeout", defaultTimeout, "Per-domain check timeout (e.g. 2s, 500ms)")
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

	service, err := checker.NewService(checker.Config{
		Workers: *workers,
		Timeout: *timeout,
		DNS:     checker.NewNetDNSResolver(),
	})
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	results := service.CheckDomains(domains)
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
}
