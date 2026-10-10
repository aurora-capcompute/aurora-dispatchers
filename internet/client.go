package internet

// The HTTP client every network driver sends through. It bounds the request
// and the response, checks every hop against the allowlist, refuses private
// addresses after DNS resolution, and drops host-held credentials on a
// redirect that leaves their origin.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"syscall"
	"time"
)

const (
	DefaultTimeout          = 10 * time.Second
	DefaultMaxResponseBytes = 64 * 1024
	DefaultMaxRequestBytes  = 1 << 20
	// DefaultMaxRedirects caps the redirect chain. A custom CheckRedirect
	// replaces net/http's built-in 10-hop ceiling, so the count must be
	// re-imposed here or a hostile server can loop the client until timeout.
	DefaultMaxRedirects = 10
)

// Client makes allowlisted HTTP requests with a bounded response body. Build one
// with NewConfiguredClient: its transport carries the SSRF dial guard and the
// configured bounds.
type Client struct {
	Policy          Policy
	HTTPClient      *http.Client
	Timeout         time.Duration
	MaxBytes        int64
	MaxRequestBytes int64
	// AllowPrivateNetwork lifts the SSRF guard. By default the client refuses
	// to connect to a resolved address that is not public (loopback, private,
	// link-local such as the 169.254.169.254 metadata endpoint), so an
	// allowlisted public name that resolves to an internal address cannot reach
	// it. Set it only for a grant that is meant to reach an internal service.
	AllowPrivateNetwork bool
}

// NewConfiguredClient builds a client for policy. A zero bound takes its
// default.
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
	// A dial-time guard, in addition to the policy: net.Dialer.Control runs after
	// DNS resolution with the actual IP about to be connected, so it catches a
	// name that resolves to a private address and defeats DNS rebinding (the
	// resolved IP, not the requested name, is what is checked).
	dialer := &net.Dialer{
		Timeout: client.Timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			if client.AllowPrivateNetwork {
				return nil
			}
			return GuardDialAddress(address)
		},
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Bound response header size explicitly — Go's default is 10 MiB — so a
	// hostile server cannot make the client buffer oversized headers. The body is
	// separately bounded by readBounded.
	transport.MaxResponseHeaderBytes = 1 << 20 // 1 MiB
	transport.DialContext = dialer.DialContext
	client.HTTPClient = &http.Client{
		Timeout:   client.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= DefaultMaxRedirects {
				return fmt.Errorf("stopped after %d redirects", DefaultMaxRedirects)
			}
			// A host-held credential is bound to the origin it was injected for.
			// The moment a redirect leaves that origin (a different host, or a
			// downgrade to http), drop every injected header — otherwise the hop
			// exfiltrates a custom credential header (X-Api-Key, Private-Token, …)
			// to another allowlisted host, which Go's stdlib does not prevent.
			if cred, ok := injectedCredentialFrom(req.Context()); ok && OriginOf(req.URL) != cred.origin {
				for _, name := range cred.headers {
					req.Header.Del(name)
				}
			}
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
	target, err := url.Parse(strings.TrimSpace(request.URL))
	if err != nil {
		return Response{}, fmt.Errorf("parse url: %w", err)
	}
	if err := c.Policy.Check(method, target); err != nil {
		return Response{}, err
	}
	if int64(len(request.Body)) > c.MaxRequestBytes {
		return Response{}, fmt.Errorf("request body exceeds %d bytes", c.MaxRequestBytes)
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

	httpResponse, err := c.HTTPClient.Do(httpRequest)
	if err != nil {
		return Response{}, err
	}
	defer httpResponse.Body.Close()

	content, truncated, err := readBounded(httpResponse.Body, c.MaxBytes)
	if err != nil {
		return Response{}, fmt.Errorf("read response body: %w", err)
	}
	return Response{
		URL:       httpResponse.Request.URL.String(),
		Status:    httpResponse.StatusCode,
		Headers:   flattenHeader(httpResponse.Header),
		Body:      content,
		Truncated: truncated,
	}, nil
}

func readBounded(reader io.Reader, maxBytes int64) (string, bool, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return "", false, err
	}
	if int64(len(data)) > maxBytes {
		return string(data[:maxBytes]), true, nil
	}
	return string(data), false, nil
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

// GuardDialAddress refuses a connection whose resolved address is not a public
// unicast IP — loopback, RFC 1918 / ULA private, link-local (incl. the
// 169.254.169.254 metadata endpoint), unspecified, or multicast. `address` is
// the post-resolution host:port net.Dialer.Control receives, so this holds even
// when a public-looking name resolves to an internal address.
func GuardDialAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("blocked: unparseable dial address %q", address)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("blocked: dial address %q did not resolve to an IP", address)
	}
	if !isPublicIP(ip) {
		return fmt.Errorf("blocked connection to non-public address %s (set allow_private_network to permit)", ip)
	}
	return nil
}

// isPublicIP reports whether ip is a globally routable unicast address — the
// only class the internet driver dials without an explicit private-network opt-in.
func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	return !cgnatBlock.Contains(ip)
}

// cgnatBlock is RFC 6598 carrier-grade NAT (100.64.0.0/10). net.IP.IsPrivate
// does not cover it, yet some clouds route internal/metadata-adjacent services
// there, so the SSRF guard must treat it as non-public.
var cgnatBlock = func() *net.IPNet {
	_, block, _ := net.ParseCIDR("100.64.0.0/10")
	return block
}()

// injectedCredential records a host-held credential attached to a request and
// the origin (scheme://host) it is bound to, threaded through the request
// context so the redirect handler can drop it the instant a hop leaves that
// origin — Go's stdlib strips only Authorization/Cookie across hosts, never a
// custom credential header.
type injectedCredential struct {
	origin  string
	headers []string
}

type injectedCredentialKey struct{}

// WithInjectedCredential marks ctx with a host-held credential bound to origin
// (lowercased scheme://host[:port]) and the header names carrying it. The
// internet client strips those headers on any redirect that leaves the origin.
func WithInjectedCredential(ctx context.Context, origin string, headers []string) context.Context {
	return context.WithValue(ctx, injectedCredentialKey{}, injectedCredential{origin: strings.ToLower(origin), headers: headers})
}

func injectedCredentialFrom(ctx context.Context) (injectedCredential, bool) {
	v, ok := ctx.Value(injectedCredentialKey{}).(injectedCredential)
	return v, ok
}

// OriginOf renders a URL's lowercased scheme://host[:port] — the identity a
// host-held credential is bound to.
func OriginOf(u *url.URL) string { return strings.ToLower(u.Scheme + "://" + u.Host) }
