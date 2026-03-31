# Email Checker Tool

A stdlib-only Go CLI for checking domain email DNS posture at scale.

For each domain, it checks:

- MX record presence
- SPF TXT record presence (`v=spf1`)
- DMARC TXT record presence (`v=DMARC1` under `_dmarc.<domain>`)

The tool supports concurrent workers, per-domain timeout, and CSV/JSON output.

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

### CSV Output (default)

```csv
domain,hasMX,hasSPF,spfRecord,hasDMARC,dmarcRecord
google.com,true,true,v=spf1 include:_spf.google.com ~all,true,v=DMARC1; p=reject
```

### JSON Output

```bash
printf "google.com\n" | ./email-checker -format json
```

```json
{"domain":"google.com","hasMX":true,"hasSPF":true,"spfRecord":"v=spf1 include:_spf.google.com ~all","hasDMARC":true,"dmarcRecord":"v=DMARC1; p=reject"}
```

## Development

```bash
go test ./...
go build ./...
```

## Notes

- Results preserve input order even when workers run concurrently.
- Timeout applies to the whole domain check, not each lookup independently.
- On partial lookup failures, the tool still outputs available data and logs warnings.

## Feature Roadmap

- Add `-resolver` flag to use a custom DNS server
- Add DKIM selector checks and BIMI record checks
- Add SPF/DMARC policy linting mode
- Add aggregate summary mode with pass/fail counts
- Add GitHub Actions CI with race detector and static analysis
