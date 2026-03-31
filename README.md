# Email Checker Tool

A stdlib-only Go CLI for checking domain email DNS posture at scale.

For each domain, it checks:

- MX record presence
- SPF TXT record presence (`v=spf1`)
- DMARC TXT record presence (`v=DMARC1` under `_dmarc.<domain>`)

The tool supports concurrent workers, per-domain timeout, CSV/JSON output, lint findings, scoring, DKIM selector checks, summary stats, and machine-readable reports.

## Requirements

- Go 1.26+

## Project Layout

```text
cmd/email-checker/main.go      # CLI entrypoint
internal/input/reader.go       # Domain input parsing and normalization
internal/checker/              # DNS checker, worker pool, timeout, result models
internal/output/writer.go      # CSV/JSON output writers
```

## Build

```bash
go build -o email-checker ./cmd/email-checker
```

## Usage

```bash
printf "google.com\nexample.com\n" | ./email-checker
```

### Flags

- `-format csv|json` Output format (default: `csv`)
- `-workers int` Number of concurrent workers (default: number of CPUs)
- `-timeout duration` Per-domain timeout (default: `3s`)
- `-resolver host:port` Custom DNS resolver, e.g. `1.1.1.1:53`
- `-resolver-proto udp|tcp` DNS transport (default: `udp`)
- `-check-dkim` Enable DKIM selector checks
- `-dkim-selectors` Comma-separated selectors (default common set)
- `-lint` Enable SPF/DMARC lint findings
- `-score` Enable weighted security score
- `-summary` Emit aggregate summary to stderr
- `-summary-format text|json` Summary format (default: `text`)
- `-failures-only` Only emit failed domains
- `-report-file path` Write full report to file
- `-report-format json|sarif` Report format (default: `json`)

### CSV Output (default)

```csv
domain,hasMX,hasSPF,spfRecord,hasDMARC,dmarcRecord,scoreTotal
google.com,true,true,v=spf1 include:_spf.google.com ~all,true,v=DMARC1; p=reject,92
```

### JSON Output

```bash
printf "google.com\n" | ./email-checker -format json
```

```json
{"domain":"google.com","hasMX":true,"hasSPF":true,"spfRecord":"v=spf1 include:_spf.google.com ~all","hasDMARC":true,"dmarcRecord":"v=DMARC1; p=reject"}
```

### Full Security Scan Example

```bash
printf "google.com\nexample.com\n" | ./email-checker \
  -format json \
  -check-dkim \
  -dkim-selectors "default,selector1,google" \
  -lint \
  -score \
  -summary \
  -summary-format json \
  -report-file report.json \
  -report-format json
```

## Notes

- Results preserve input order even when workers run concurrently.
- Timeout applies to the whole domain check, not each lookup independently.
- On partial lookup failures, the tool still outputs available data and logs warnings.
- Lint findings include severity and remediation hints.
- SARIF output enables upload into code scanning style tooling.

## Development

```bash
go test ./...
go test -race ./...
go build ./...
```

CI is configured in `.github/workflows/ci.yml` and runs formatting, vet, tests, race tests, and build.

## Advanced Roadmap

- BIMI TXT validation and logo URI sanity checks
- MTA-STS and TLS-RPT policy checks
- SPF include-chain depth checks and flattening advice
- Configurable scoring profile presets (strict, balanced, relaxed)
- Multi-output run mode (CSV to stdout + JSON report file)
