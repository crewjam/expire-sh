package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang/gddo/httputil"
	"github.com/jordic/goics"
	"golang.org/x/net/publicsuffix"
)

func NewServer() http.Handler {
	return &Server{}
}

type Server struct {
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		s.serveIndex(w, r)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/ical/") {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/ical")
		r.Header.Set("Accept", "text/calendar")
	} else if strings.HasPrefix(r.URL.Path, "/json/") {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/json")
		r.Header.Set("Accept", "application/json")
	} else if strings.HasPrefix(r.URL.Path, "/text/") {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/text")
		r.Header.Set("Accept", "text/plain")
	}

	s.serveExpirations(w, r)
}

const indexText = `
|=========|=========|=========|=========|=========|=========|=========|=========
expire.sh checks your domain and certificate expirations

Construct a calendar URL by providing a list of host names separated by commas, for 
example to monitor example.com, example.org, and example.net just add the following
calendar:

https://expire.sh/example.com,example.net

Formats
-------

Responses are available in text, JSON, or iCal formats. You can specify which 
format you want with the Accept header (with one of 'text/plain',
'application/json', or 'text/calendar')

$ curl -H "Accept: application/json" https://expire.sh/example.com
{"expirations":[{"Name":"example.com","CertificateExpires":"2020-12-02T12:00:00Z","CertificateError":null,"Domain":"example.com","DomainExpires":"2019-08-13T04:00:00Z","DomainError":null}]}

If this is inconvenient, you can also add the format you want to the front of the URL:

$ curl -v https://expire.sh/ical/example.com
< content-type: text/calendar

BEGIN:VCALENDAR
...
END:VCALENDAR


Status Code
-----------

In a slightly blatant abuse of the standard, the text and JSON responses use 
HTTP status codes to tell you if anything has gone wrong. The code '502 Bad Gateway'
means that we were not able to check at least one of the domains you specified. The
code '417 Expectation Failed' means that at least one of the domains or certificates
you provided expires soon (default: within 30 days, modify with the ttl query parameter)

Note: The status code never changes for iCal responses because that would mess up
calendar programs.

Parameters
----------

You can all the "ttl" parameter to redefine what "soon" means with respect to 
expiration.

$ curl -v https://expire.sh/text/example.com?ttl=1y

You can also use the "quiet" parameter to suppress results for any domain or 
certificate that doesn't expire soon, which can be useful for use with a cron job.

$ curl -v https://expire.sh/text/example.com?ttl=60d&quiet

`

const version = "1.0.1"

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain")
	fmt.Fprint(w, indexText)
}

type Expiration struct {
	Name               string
	CertificateExpires time.Time
	CertificateError   error
	Domain             string
	DomainExpires      time.Time
	DomainError        error
}

func (e Expiration) Text() string {
	certStr := e.CertificateExpires.String()
	if e.CertificateError != nil {
		certStr = e.CertificateError.Error()
	}

	domainStr := e.DomainExpires.String()
	if e.DomainError != nil {
		domainStr = e.DomainError.Error()
	}
	return strings.Join([]string{
		e.Name,
		certStr,
		e.Domain,
		domainStr,
	}, "\t")
}

func (e Expiration) OK(soon time.Time) bool {
	if e.CertificateError != nil {
		return false
	}
	if e.CertificateExpires.Before(soon) {
		return false
	}
	if e.DomainError != nil {
		return false
	}
	if e.DomainExpires.Before(soon) {
		return false
	}
	return true
}

func getExpirations(ctx context.Context, hostnames []string) []Expiration {
	rv := make([]Expiration, len(hostnames))
	for i, hostname := range hostnames {
		rv[i].Name = hostname
	}

	for i, hostname := range hostnames {
		rv[i].CertificateExpires, rv[i].CertificateError = getCertExpiration(ctx, hostname)
	}

	// figure out the unique domains domains
	domains := map[string]bool{}
	for i, hostname := range hostnames {
		domain, err := publicsuffix.EffectiveTLDPlusOne(hostname)
		if err != nil {
			continue
		}
		domains[domain] = true
		rv[i].Domain = domain
	}

	for domain := range domains {
		domainExpires, err := getDomainExpiration(ctx, domain)
		for i := range rv {
			if rv[i].Domain == domain {
				rv[i].DomainError = err
				rv[i].DomainExpires = domainExpires
			}
		}
	}
	return rv
}

func (s *Server) serveExpirationsJSON(w http.ResponseWriter, r *http.Request, expirations []Expiration) {
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Expirations []Expiration `json:"expirations"`
	}{
		Expirations: expirations,
	})
}

func (s *Server) serveExpirationsText(w http.ResponseWriter, r *http.Request, expirations []Expiration) {
	w.Header().Add("Content-Type", "text/plain")
	for _, exp := range expirations {
		fmt.Fprintln(w, exp.Text())
	}
}

type Expirations []Expiration

func (expirations Expirations) EmitICal() goics.Componenter {
	c := goics.NewComponent()
	c.SetType("VCALENDAR")
	c.AddProperty("CALSCAL", "GREGORIAN")
	c.AddProperty("PRODID;X-RICAL-TZSOURCE=TZINFO", "-//tmpo.io")

	now := time.Now()
	for _, exp := range expirations {
		s := goics.NewComponent()
		s.SetType("VEVENT")
		s.AddProperty("UID", exp.Name+"@certificates.expire.sh")
		if exp.CertificateError == nil {
			s.AddProperty(goics.FormatDateField("DTEND", exp.CertificateExpires))
			s.AddProperty(goics.FormatDateField("DTSTART", exp.CertificateExpires))
			s.AddProperty("DESCRIPTION", fmt.Sprintf("%s certificate expires", exp.Name))
			s.AddProperty("SUMMARY", fmt.Sprintf("%s certificate expires on %s", exp.Name,
				exp.CertificateExpires))
		} else {
			s.AddProperty(goics.FormatDateField("DTEND", now))
			s.AddProperty(goics.FormatDateField("DTSTART", now))
			s.AddProperty("DESCRIPTION", fmt.Sprintf("%s: error checking certificate", exp.Name))
			s.AddProperty("SUMMARY", fmt.Sprintf("checking certificate for %s: %s", exp.Name,
				exp.CertificateError))
		}
		c.AddComponent(s)

		s = goics.NewComponent()
		s.SetType("VEVENT")
		s.AddProperty("UID", exp.Name+"@domain.expire.sh")
		if exp.DomainError == nil {
			s.AddProperty(goics.FormatDateField("DTEND", exp.DomainExpires))
			s.AddProperty(goics.FormatDateField("DTSTART", exp.DomainExpires))
			s.AddProperty("DESCRIPTION", fmt.Sprintf("%s domain expires", exp.Name))
			s.AddProperty("SUMMARY", fmt.Sprintf("The domain registration for %s (%s) expires on %s",
				exp.Name, exp.Domain, exp.DomainExpires))
		} else {
			s.AddProperty(goics.FormatDateField("DTEND", now))
			s.AddProperty(goics.FormatDateField("DTSTART", now))
			s.AddProperty("DESCRIPTION", fmt.Sprintf("%s: error checking domain expiration", exp.Name))
			s.AddProperty("SUMMARY", fmt.Sprintf("checking domain expiration for %s: %s", exp.Name,
				exp.DomainError))
		}
		c.AddComponent(s)
	}

	return c

}

func (s *Server) serveExpirationsIcal(w http.ResponseWriter, r *http.Request, expirations []Expiration) {
	w.Header().Set("Content-type", "text/calendar")
	w.Header().Set("charset", "utf-8")
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("filename", "calendar.ics")
	goics.NewICalEncode(w).Encode(Expirations(expirations))
}

func (s *Server) serveExpirations(w http.ResponseWriter, r *http.Request) {
	hostnames := strings.Split(strings.Trim(r.URL.Path, "/"), ",")
	expirations := getExpirations(r.Context(), hostnames)

	contentType := httputil.NegotiateContentType(r, []string{
		"application/json",
		"text/plain",
		"text/calendar",
	}, "text/plain")

	ttl := time.Hour * 24 * 30
	if ttlStr := r.FormValue("ttl"); ttlStr != "" {
		var err error
		ttl, err = time.ParseDuration(ttlStr)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Cannot parse ttl parameter:", err.Error())
			return
		}
	}

	soon := time.Now().Add(-1 * ttl)
	hasError := false
	hasExpirationSoon := false
	for _, expiration := range expirations {
		if expiration.CertificateError != nil {
			hasError = true
		} else if expiration.CertificateExpires.Before(soon) {
			hasExpirationSoon = true
		}
		if expiration.DomainError != nil {
			hasError = true
		} else if expiration.DomainExpires.Before(soon) {
			hasExpirationSoon = true
		}
	}

	quiet := r.URL.Query()["quiet"] != nil
	if quiet {
		filteredExpirations := expirations[:0]
		for _, expiration := range expirations {
			if expiration.OK(soon) {
				continue
			}
			filteredExpirations = append(filteredExpirations, expiration)
		}
		expirations = filteredExpirations
	}

	// don't do content type detection for iCal because it would
	// break calendar programs
	if contentType != "text/calendar" {
		if hasError {
			w.WriteHeader(http.StatusBadGateway)
		} else if hasExpirationSoon {
			w.WriteHeader(http.StatusExpectationFailed)
		}
	}

	switch contentType {
	case "application/json":
		s.serveExpirationsJSON(w, r, expirations)
		return
	case "text/plain":
		s.serveExpirationsText(w, r, expirations)
		return
	case "text/calendar":
		s.serveExpirationsIcal(w, r, expirations)
		return
	}

}

func main() {
	s := NewServer()
	http.Handle("/", s)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("Defaulting to port %s", port)
	}

	log.Printf("Listening on port %s", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}
