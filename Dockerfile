FROM golang:1.26-alpine AS builder

WORKDIR /src

COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/email-checker ./cmd/email-checker

FROM gcr.io/distroless/static:nonroot

COPY --from=builder /out/email-checker /usr/local/bin/email-checker

ENTRYPOINT ["/usr/local/bin/email-checker"]
