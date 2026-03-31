package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"email-checker-tool/internal/checker"
)

const (
	FormatCSV  = "csv"
	FormatJSON = "json"
)

type Writer interface {
	WriteHeader() error
	WriteResult(result checker.DomainResult) error
	Flush() error
}

type csvWriter struct {
	writer *csv.Writer
}

func (w *csvWriter) WriteHeader() error {
	return w.writer.Write([]string{
		"domain",
		"hasMX",
		"hasSPF",
		"spfRecord",
		"hasDMARC",
		"dmarcRecord",
		"hasBIMI",
		"bimiRecord",
		"hasMTASTS",
		"mtaSTSRecord",
		"hasTLSRPT",
		"tlsRPTRecord",
		"scoreTotal",
	})
}

func (w *csvWriter) WriteResult(result checker.DomainResult) error {
	row := []string{
		result.Domain,
		strconv.FormatBool(result.HasMX),
		strconv.FormatBool(result.HasSPF),
		result.SPFRecord,
		strconv.FormatBool(result.HasDMARC),
		result.DMARCRecord,
		strconv.FormatBool(result.HasBIMI),
		result.BIMIRecord,
		strconv.FormatBool(result.HasMTASTS),
		result.MTASTSRecord,
		strconv.FormatBool(result.HasTLSRPT),
		result.TLSRPTRecord,
		scoreTotal(result),
	}

	return w.writer.Write(row)
}

func scoreTotal(result checker.DomainResult) string {
	if result.Score == nil {
		return ""
	}
	return strconv.Itoa(result.Score.Total)
}

func (w *csvWriter) Flush() error {
	w.writer.Flush()
	return w.writer.Error()
}

type jsonWriter struct {
	encoder *json.Encoder
}

func (w *jsonWriter) WriteHeader() error {
	return nil
}

func (w *jsonWriter) WriteResult(result checker.DomainResult) error {
	return w.encoder.Encode(result)
}

func (w *jsonWriter) Flush() error {
	return nil
}

func NewWriter(format string, out io.Writer) (Writer, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case FormatCSV:
		return &csvWriter{writer: csv.NewWriter(out)}, nil
	case FormatJSON:
		return &jsonWriter{encoder: json.NewEncoder(out)}, nil
	default:
		return nil, fmt.Errorf("unsupported format %q (use %q or %q)", format, FormatCSV, FormatJSON)
	}
}
