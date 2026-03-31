package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	formatCSV  = "csv"
	formatJSON = "json"
)

type domainResult struct {
	Domain      string `json:"domain"`
	HasMX       bool   `json:"hasMX"`
	HasSPF      bool   `json:"hasSPF"`
	SPFRecord   string `json:"spfRecord,omitempty"`
	HasDMARC    bool   `json:"hasDMARC"`
	DMARCRecord string `json:"dmarcRecord,omitempty"`
}

type resultWriter interface {
	WriteHeader() error
	WriteResult(result domainResult) error
	Flush() error
}

type csvResultWriter struct {
	writer *csv.Writer
}

func (w *csvResultWriter) WriteHeader() error {
	return w.writer.Write([]string{"domain", "hasMX", "hasSPF", "spfRecord", "hasDMARC", "dmarcRecord"})
}

func (w *csvResultWriter) WriteResult(result domainResult) error {
	row := []string{
		result.Domain,
		strconv.FormatBool(result.HasMX),
		strconv.FormatBool(result.HasSPF),
		result.SPFRecord,
		strconv.FormatBool(result.HasDMARC),
		result.DMARCRecord,
	}

	return w.writer.Write(row)
}

func (w *csvResultWriter) Flush() error {
	w.writer.Flush()
	return w.writer.Error()
}

type jsonResultWriter struct {
	encoder *json.Encoder
}

func (w *jsonResultWriter) WriteHeader() error {
	return nil
}

func (w *jsonResultWriter) WriteResult(result domainResult) error {
	return w.encoder.Encode(result)
}

func (w *jsonResultWriter) Flush() error {
	return nil
}

func main() {
	format := flag.String("format", formatCSV, "Output format: csv or json")
	flag.Parse()

	writer, err := newResultWriter(*format, os.Stdout)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	scanner := bufio.NewScanner(os.Stdin)
	if err := writer.WriteHeader(); err != nil {
		log.Fatalf("error: could not write output header: %v", err)
	}

	for scanner.Scan() {
		domain := normalizeDomain(scanner.Text())
		if domain == "" {
			continue
		}

		result, err := checkDomain(domain)
		if err != nil {
			log.Printf("warning: could not fully check %q: %v", domain, err)
		}

		if err := writer.WriteResult(result); err != nil {
			log.Fatalf("error: could not write output row: %v", err)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("error: could not read from input: %v", err)
	}

	if err := writer.Flush(); err != nil {
		log.Fatalf("error: could not flush output: %v", err)
	}
}

func newResultWriter(format string, out io.Writer) (resultWriter, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case formatCSV:
		return &csvResultWriter{writer: csv.NewWriter(out)}, nil
	case formatJSON:
		return &jsonResultWriter{encoder: json.NewEncoder(out)}, nil
	default:
		return nil, fmt.Errorf("unsupported format %q (use %q or %q)", format, formatCSV, formatJSON)
	}
}

func checkDomain(domain string) (domainResult, error) {
	result := domainResult{Domain: domain}
	var errs []string

	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		errs = append(errs, fmt.Sprintf("mx: %v", err))
	}
	if len(mxRecords) > 0 {
		result.HasMX = true
	}

	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		errs = append(errs, fmt.Sprintf("spf: %v", err))
	}
	if spfRecord, ok := findRecordByPrefix(txtRecords, "v=spf1"); ok {
		result.HasSPF = true
		result.SPFRecord = spfRecord
	}

	dmarcRecords, err := net.LookupTXT("_dmarc." + domain)
	if err != nil {
		errs = append(errs, fmt.Sprintf("dmarc: %v", err))
	}
	if dmarcRecord, ok := findRecordByPrefix(dmarcRecords, "v=DMARC1"); ok {
		result.HasDMARC = true
		result.DMARCRecord = dmarcRecord
	}

	if len(errs) > 0 {
		return result, errors.New(strings.Join(errs, "; "))
	}

	return result, nil
}

func normalizeDomain(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func findRecordByPrefix(records []string, prefix string) (string, bool) {
	normalizedPrefix := strings.ToLower(prefix)
	for _, record := range records {
		trimmedRecord := strings.TrimSpace(record)
		if strings.HasPrefix(strings.ToLower(trimmedRecord), normalizedPrefix) {
			return trimmedRecord, true
		}
	}

	return "", false
}
