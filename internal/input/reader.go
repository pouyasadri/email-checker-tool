package input

import (
	"bufio"
	"io"
	"strings"
)

func ReadDomains(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)
	domains := make([]string, 0)

	for scanner.Scan() {
		domain := NormalizeDomain(scanner.Text())
		if domain == "" {
			continue
		}
		domains = append(domains, domain)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return domains, nil
}

func NormalizeDomain(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}
