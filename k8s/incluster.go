package k8s

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// The service account paths a pod is given by the kubelet. The token is a
// projected credential that rotates (roughly hourly by default), so it is
// re-read rather than captured once; the CA verifies the API server's
// certificate (the driver never skips verification).
const (
	saDir           = "/var/run/secrets/kubernetes.io/serviceaccount"
	saTokenFile     = saDir + "/token"
	saCAFile        = saDir + "/ca.crt"
	saNamespaceFile = saDir + "/namespace"
	// tokenReadInterval bounds how stale an in-cluster token read may be: short
	// enough that a rotated token is picked up promptly, long enough that a burst
	// of requests does not stat the file every time.
	tokenReadInterval = 30 * time.Second
)

// tokenSource yields the current bearer token for the API server. In-cluster it
// re-reads the rotating projected token; an explicit token returns its value
// verbatim.
type tokenSource interface {
	token() (string, error)
}

// staticToken is a fixed bearer token (the explicit-config path). The value is
// resolved host-side from a secret reference and never reaches the guest.
type staticToken string

func (s staticToken) token() (string, error) {
	if s == "" {
		return "", fmt.Errorf("no bearer token configured")
	}
	return string(s), nil
}

// fileToken re-reads a token file, caching the value for tokenReadInterval so a
// rotated projected token is picked up without a file read per request. A
// transient read error falls back to the last good value rather than failing a
// request outright.
type fileToken struct {
	path string
	now  func() time.Time

	mu     sync.Mutex
	cached string
	readAt time.Time
}

func newFileToken(path string) *fileToken { return &fileToken{path: path, now: time.Now} }

func (f *fileToken) token() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cached != "" && f.now().Sub(f.readAt) < tokenReadInterval {
		return f.cached, nil
	}
	raw, err := os.ReadFile(f.path)
	if err != nil {
		if f.cached != "" {
			return f.cached, nil // tolerate a transient read; use the last good token
		}
		return "", fmt.Errorf("read service account token: %w", err)
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		if f.cached != "" {
			return f.cached, nil
		}
		return "", fmt.Errorf("service account token file is empty")
	}
	f.cached = value
	f.readAt = f.now()
	return f.cached, nil
}

// Access is the resolved host-side facts to reach one API server: the base URL,
// the cluster CA (PEM; empty means verify against the system roots), and the
// token source. None of it is guest-supplied; the registry threads it into
// NewClient opaquely (its fields are package-private).
type Access struct {
	endpoint  string // https://host[:port], no trailing slash
	caPEM     []byte
	tokens    tokenSource
	namespace string // the pod's own namespace, when known (a convenience default)
}

// InClusterAccess resolves access from the pod's service account: the API server
// from the injected env, the CA and token from the projected files. It also
// returns the current token value so the caller can fingerprint the credential
// for audit. It fails when any piece is missing — the caller then reports that
// the grant needs either an in-cluster service account or explicit config.
func InClusterAccess() (Access, string, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return Access{}, "", fmt.Errorf("not in a cluster: KUBERNETES_SERVICE_HOST/PORT are unset")
	}
	caPEM, err := os.ReadFile(saCAFile)
	if err != nil {
		return Access{}, "", fmt.Errorf("read cluster CA: %w", err)
	}
	token := newFileToken(saTokenFile)
	value, err := token.token()
	if err != nil {
		return Access{}, "", err
	}
	ns := ""
	if raw, err := os.ReadFile(saNamespaceFile); err == nil {
		ns = strings.TrimSpace(string(raw))
	}
	return Access{
		endpoint:  "https://" + net.JoinHostPort(host, port),
		caPEM:     caPEM,
		tokens:    token,
		namespace: ns,
	}, value, nil
}

// ExplicitAccess resolves access from manifest-supplied config: an https
// endpoint, an already-resolved bearer token (from a secret reference), and an
// optional CA PEM (empty verifies against the system roots).
func ExplicitAccess(endpoint, caPEM, token string) (Access, error) {
	normalized, err := NormalizeEndpoint(endpoint)
	if err != nil {
		return Access{}, err
	}
	if strings.TrimSpace(token) == "" {
		return Access{}, fmt.Errorf("explicit kubernetes config requires a bearer token")
	}
	return Access{endpoint: normalized, caPEM: []byte(caPEM), tokens: staticToken(token)}, nil
}

// NormalizeEndpoint validates an API server URL: https only (a bearer token must
// ride TLS), a host, and no path/query/fragment/userinfo. Returns it without a
// trailing slash. Exported so the registry can validate and canonicalize an
// explicit endpoint at manifest-normalization time, not only at activation.
func NormalizeEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", fmt.Errorf("endpoint is empty")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse endpoint %q: %w", endpoint, err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return "", fmt.Errorf("endpoint %q must be https (a bearer token must ride TLS)", endpoint)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("endpoint %q has no host", endpoint)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.Trim(parsed.Path, "/") != "" {
		return "", fmt.Errorf("endpoint %q must be a scheme and host only", endpoint)
	}
	return strings.ToLower(parsed.Scheme) + "://" + parsed.Host, nil
}

// tlsTransport builds an HTTP transport that verifies the API server against the
// given CA (or the system roots when caPEM is empty) — never InsecureSkipVerify.
// Response header size is bounded so a hostile endpoint cannot make the client
// buffer oversized headers; the body is separately bounded by the client.
func tlsTransport(caPEM []byte, dialTimeout time.Duration) (*http.Transport, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxResponseHeaderBytes = 1 << 20
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("cluster CA is not valid PEM")
		}
		tlsConfig.RootCAs = pool
	}
	transport.TLSClientConfig = tlsConfig
	// The API server host is fixed by host-side config and is never guest-supplied,
	// so — unlike the internet driver — there is no SSRF surface to guard here: the
	// guest chooses the resource path, never the host dialed.
	transport.DialContext = (&net.Dialer{Timeout: dialTimeout}).DialContext
	return transport, nil
}
