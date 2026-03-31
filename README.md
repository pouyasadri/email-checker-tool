# Email Checker Tool

A lightweight Go CLI that reads domains from standard input and checks for:

- MX record presence
- SPF TXT record presence (`v=spf1`)
- DMARC TXT record presence (`v=DMARC1` under `_dmarc.<domain>`)

It is intentionally stdlib-only and ready to run in pipelines.

## Requirements

- Go 1.26+

## Install

```bash
go build -o email-checker-tool .
```

## Usage

Pipe domains into the binary:

```bash
printf "google.com\nexample.com\n" | ./email-checker-tool
```

### Flags

- `-format csv|json` Output format (default: `csv`)

## Output Examples

### CSV (default)

```csv
domain,hasMX,hasSPF,spfRecord,hasDMARC,dmarcRecord
google.com,true,true,v=spf1 include:_spf.google.com ~all,true,v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com
```

### JSON

```bash
printf "google.com\n" | ./email-checker-tool -format json
```

```json
{"domain":"google.com","hasMX":true,"hasSPF":true,"spfRecord":"v=spf1 include:_spf.google.com ~all","hasDMARC":true,"dmarcRecord":"v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com"}
```

## Development

```bash
go test ./...
go build ./...
```

## Roadmap

- Add `-workers` for concurrent DNS checks
- Add `-timeout` for per-domain lookup limits
- Add optional resolver override (custom DNS server)
- Add summary output mode for pass/fail totals
