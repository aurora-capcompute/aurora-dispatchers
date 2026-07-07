// Package internet is the HTTP capability driver: a bounded, allowlisted client
// a program uses to make web requests of any method, and the policy that
// constrains which (method, host) pairs a grant permits.
package internet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"
)

// Capability is the canonical syscall name a core.internet grant publishes.
const Capability = "internet.fetch"

const (
	DefaultTimeout          = 10 * time.Second
	DefaultMaxResponseBytes = 64 * 1024
	DefaultMaxRequestBytes  = 1 << 20
)

// AnyMethod is the method wildcard in a policy rule: it matches every HTTP
// method against the rule's origin.
const AnyMethod = "*"

// Request is one HTTP request a program asks the host to make. Any method is
// allowed; the grant's Policy decides which (method, host) pairs are permitted.
type Request struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// Response is the outcome the program observes: the final URL (after redirects),
// the status code, the response headers, and the bounded body.
type Response struct {
	URL     string            `json:"url"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body"`
}

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
// its declared permissions into an allowlist without round-tripping through the
// string form.
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

// ParseAllowlist reads the string form of a policy — comma-separated
// `METHOD:origin` entries, where METHOD may be "*" and origin may be "*" or a
// bare host — for operator configuration.
func ParseAllowlist(raw string) (Policy, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Policy{}, nil
	}
	var rules []Rule
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		method, origin, ok := strings.Cut(entry, ":")
		if !ok {
			return Policy{}, fmt.Errorf("invalid allowlist entry %q: want METHOD:origin", entry)
		}
		rule, err := NewRule(method, origin)
		if err != nil {
			return Policy{}, fmt.Errorf("allowlist entry %q: %w", entry, err)
		}
		rules = append(rules, rule)
	}
	return Policy{rules: rules}, nil
}

// Check reports whether method+target is allowlisted, and validates the target
// is a credential-free http(s) URL.
func (p Policy) Check(method string, target *url.URL) error {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return errors.New("method is required")
	}
	if target == nil {
		return errors.New("url is required")
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

// Allows is Check for a raw URL string.
func (p Policy) Allows(method string, rawURL string) error {
	target, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	return p.Check(method, target)
}

// Client makes allowlisted HTTP requests with a bounded response body. The zero
// value is unusable; build one with NewClient or NewConfiguredClient.
type Client struct {
	Policy          Policy
	HTTPClient      *http.Client
	Timeout         time.Duration
	MaxBytes        int64
	MaxRequestBytes int64
}

func NewClient(policy Policy) *Client {
	return NewConfiguredClient(policy, DefaultTimeout, DefaultMaxResponseBytes, DefaultMaxRequestBytes)
}

func NewConfiguredClient(policy Policy, timeout time.Duration, maxResponseBytes, maxRequestBytes int64) *Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if maxResponseBytes <= 0 {
		maxResponseBytes = DefaultMaxResponseBytes
	}
	if maxRequestBytes <= 0 {
		maxRequestBytes = DefaultMaxRequestBytes
	}
	client := &Client{
		Policy:          policy,
		Timeout:         timeout,
		MaxBytes:        maxResponseBytes,
		MaxRequestBytes: maxRequestBytes,
	}
	client.HTTPClient = &http.Client{
		Timeout: client.Timeout,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			// Re-check every redirect hop against the policy.
			return client.Policy.Check(req.Method, req.URL)
		},
	}
	return client
}

// Do makes one request. The method is unconstrained by the client — the policy
// decides — so a grant that allowlists POST can write, one that allowlists only
// GET can read. The response body is read up to MaxBytes.
func (c *Client) Do(ctx context.Context, request Request) (Response, error) {
	method := strings.ToUpper(strings.TrimSpace(request.Method))
	if method == "" {
		return Response{}, errors.New("method is required")
	}
	target, err := url.Parse(strings.TrimSpace(request.URL))
	if err != nil {
		return Response{}, fmt.Errorf("parse url: %w", err)
	}
	if err := c.Policy.Check(method, target); err != nil {
		return Response{}, err
	}
	if int64(len(request.Body)) > c.maxRequestBytes() {
		return Response{}, fmt.Errorf("request body exceeds %d bytes", c.maxRequestBytes())
	}

	var body io.Reader
	if request.Body != "" {
		body = strings.NewReader(request.Body)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return Response{}, fmt.Errorf("create request: %w", err)
	}
	httpRequest.Header.Set("Accept", "*/*")
	for name, value := range request.Headers {
		httpRequest.Header.Set(name, value)
	}

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = NewClient(c.Policy).HTTPClient
	}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return Response{}, err
	}
	defer httpResponse.Body.Close()

	content, err := readBounded(httpResponse.Body, c.maxBytes())
	if err != nil {
		return Response{}, fmt.Errorf("read response body: %w", err)
	}
	return Response{
		URL:     httpResponse.Request.URL.String(),
		Status:  httpResponse.StatusCode,
		Headers: flattenHeader(httpResponse.Header),
		Body:    content,
	}, nil
}

func (c *Client) maxBytes() int64 {
	if c == nil || c.MaxBytes <= 0 {
		return DefaultMaxResponseBytes
	}
	return c.MaxBytes
}

func (c *Client) maxRequestBytes() int64 {
	if c == nil || c.MaxRequestBytes <= 0 {
		return DefaultMaxRequestBytes
	}
	return c.MaxRequestBytes
}

func validateScheme(scheme string) error {
	switch strings.ToLower(scheme) {
	case "http", "https":
		return nil
	default:
		return fmt.Errorf("scheme %q is not allowed", scheme)
	}
}

// flattenHeader renders response headers as a name→value map (first value per
// name), enough for a program to read content type and the like.
func flattenHeader(header http.Header) map[string]string {
	if len(header) == 0 {
		return nil
	}
	out := make(map[string]string, len(header))
	for name, values := range header {
		if len(values) > 0 {
			out[textproto.CanonicalMIMEHeaderKey(name)] = values[0]
		}
	}
	return out
}

func readBounded(reader io.Reader, maxBytes int64) (string, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > maxBytes {
		data = data[:maxBytes]
	}
	return string(data), nil
}
