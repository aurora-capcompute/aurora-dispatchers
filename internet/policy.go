package internet

// The allowlist: the (method, origin) pairs a grant permits.

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Policy is a grant's allowlist: the (method, origin) pairs it may request. A
// rule with AnyMethod matches any method; a rule with AnyHost matches any host.
type Policy struct {
	rules []Rule
}

// Rule permits one method (or AnyMethod) against one origin (or any host).
type Rule struct {
	Method  string // uppercase HTTP method, or AnyMethod
	Scheme  string // lowercase; empty when AnyHost
	Host    string // lowercase; empty when AnyHost
	AnyHost bool
}

// NewPolicy builds a policy from explicit rules — the seam a grant uses to turn
// its declared permissions into an allowlist.
func NewPolicy(rules ...Rule) Policy {
	return Policy{rules: append([]Rule(nil), rules...)}
}

// NewRule builds one allowlist rule from a method (an HTTP method or AnyMethod)
// and a domain: a bare host allows https for it, an explicit scheme://host is
// honored, and "*" matches any host.
func NewRule(method, domain string) (Rule, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return Rule{}, errors.New("method is required")
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return Rule{}, errors.New("domain is required")
	}
	if domain == "*" {
		return Rule{Method: method, AnyHost: true}, nil
	}
	origin := domain
	if !strings.Contains(origin, "://") {
		origin = "https://" + origin
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return Rule{}, fmt.Errorf("parse origin %q: %w", domain, err)
	}
	if err := validateScheme(parsed.Scheme); err != nil {
		return Rule{}, fmt.Errorf("origin %q: %w", domain, err)
	}
	if parsed.Host == "" {
		return Rule{}, fmt.Errorf("origin %q has no host", domain)
	}
	if parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return Rule{}, fmt.Errorf("origin %q must be a scheme and host only", domain)
	}
	return Rule{Method: method, Scheme: strings.ToLower(parsed.Scheme), Host: strings.ToLower(parsed.Host)}, nil
}

// Check reports whether method+target is allowlisted, and validates the target
// is a credential-free http(s) URL.
func (p Policy) Check(method string, target *url.URL) error {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return errors.New("method is required")
	}
	if err := validateScheme(target.Scheme); err != nil {
		return err
	}
	if target.Host == "" {
		return errors.New("url host is required")
	}
	if target.User != nil {
		return errors.New("url credentials are not allowed")
	}
	scheme := strings.ToLower(target.Scheme)
	host := strings.ToLower(target.Host)
	for _, rule := range p.rules {
		methodOK := rule.Method == AnyMethod || rule.Method == method
		hostOK := rule.AnyHost || (rule.Scheme == scheme && rule.Host == host)
		if methodOK && hostOK {
			return nil
		}
	}
	return fmt.Errorf("%s %s://%s is not allowlisted", method, scheme, host)
}

func validateScheme(scheme string) error {
	switch strings.ToLower(scheme) {
	case "http", "https":
		return nil
	default:
		return fmt.Errorf("scheme %q is not allowed", scheme)
	}
}

// LoopbackHost reports whether host (optionally host:port) is loopback, where
// plain HTTP carries no wire to sniff — the sole exception to the TLS
// requirement for credential injection.
func LoopbackHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
