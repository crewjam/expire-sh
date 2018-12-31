package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/araddon/dateparse"
	"github.com/domainr/whois"
)

// getDomainExpiration returns the expiration date for a domain.
//
// This is flaky because there seems to be no general standard for how
// whois information is formatted. Ugh.
func getDomainExpiration(ctx context.Context, domain string) (time.Time, error) {
	request, err := whois.NewRequest(domain)
	if err != nil {
		return time.Time{}, err
	}
	response, err := whois.DefaultClient.FetchContext(ctx, request)
	if err != nil {
		return time.Time{}, err
	}
	text, err := response.Text()
	if err != nil {
		return time.Time{}, err
	}

	bodyReader, err := response.Reader()
	if err != nil {
		return time.Time{}, err
	}

	// scan the output of the whois response for a line with
	// one of the expirationKeywords that indicate an expiration date
	s := bufio.NewScanner(bodyReader)
	for s.Scan() {
		line := strings.ToLower(s.Text())
		for _, keyword := range expirationKeywords {
			if strings.Contains(line, keyword) {
				for i := 0; i < len(line); i++ {
					possibleDateStr := s.Text()[i:]
					possibleDate, err := dateparse.ParseAny(possibleDateStr)
					if err == nil {
						// the first time we encounter a valid date, we've got our
						// answer
						return possibleDate, nil
					}
				}
			}
		}
	}

	log.Printf("cannot determine expiration date for %s from whois record %q", domain, text)
	return time.Time{}, fmt.Errorf("cannot determine expiration date from whois record")
}

var expirationKeywords = []string{
	"expiry",
	"expiration",
	"expires",
	"registered through",
	"expired",
	"expire",
	"expired",
	"domain_datebilleduntil",
	"paid-till",
	"renewal date",
	"fecha de vencimiento",
}
