// Package k8s is a read-only, deliberately minimal Kubernetes capability driver.
// A grant exposes exactly one operation — get one object by name — against an
// author-declared allowlist of (resource, namespace) pairs. There is no write
// path anywhere in this package, and no list, pagination, selector, or
// etcd-quorum read either: the client only ever builds a single-object GET
// served from the API server's watch cache. That is the one Kubernetes read
// that is provably light — O(1), cached, and byte-bounded — so no manifest,
// guest, or bug can turn this driver into anything heavy on, or destructive to,
// the cluster.
//
// (list and its heavier relatives were intentionally removed for now; they can
// return later as an additional operation without changing get's shape.)
package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aurora-capcompute/capcompute/sys"
)

// Capability is the name a core.kubernetes grant publishes. get is the only
// operation (the ADT discriminator inside the call args).
const Capability = "core.kubernetes"

const (
	// VerbGet reads one named object — the only verb this driver knows.
	VerbGet = "get"

	DefaultTimeout          = 10 * time.Second
	DefaultMaxResponseBytes = 256 * 1024
	DefaultRequestsPerSec   = 5
	DefaultBurst            = 5

	// maxRetryAfter caps how long a server-supplied Retry-After can park a grant,
	// so a misconfigured or hostile endpoint cannot freeze it indefinitely.
	maxRetryAfter = 2 * time.Minute
	// userAgent identifies the client to the API server audit log.
	userAgent = "aurora-k8s-reader"
)

// Request is one read a program asks the host to perform: one object identified
// by resource type, namespace, and name. The resource/namespace/name are the
// guest-supplied fields, each validated and checked against the grant's
// allowlist before any request is built.
type Request struct {
	Operation string `json:"operation"`
	Group     string `json:"group,omitempty"`
	Version   string `json:"version,omitempty"`
	Resource  string `json:"resource"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	// MetadataOnly, when set true, returns only object metadata (names, labels,
	// timestamps) rather than the whole object. It can only tighten: a grant that
	// forces metadata-only ignores a false here.
	MetadataOnly *bool `json:"metadata_only,omitempty"`
}

// Response is what the program observes: the API server's HTTP status and the
// bounded JSON body (the object, or a Status object for an error).
type Response struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

// Permission is one entry of a grant's allowlist: a resource type and the
// namespaces it may be read in, plus its data-flow policy. It is host-authored
// trusted policy — the path a request is built from comes from here, never from
// the guest's raw strings.
type Permission struct {
	Group    string
	Version  string
	Resource string
	// Verbs are the operations granted on this resource, keyed by verb name.
	// Only "get" is currently implemented; the set is the forward-compatible
	// allowlist a future operation (list, …) slots into.
	Verbs map[string]bool
	// Namespaces are the allowed namespaces; "*" means any. The guest still names
	// a concrete namespace on each get — the wildcard only removes the
	// restriction on which one. Ignored when ClusterScoped.
	Namespaces []string
	// ClusterScoped marks a non-namespaced resource (nodes, namespaces,
	// persistentvolumes). Its reads carry no namespace.
	ClusterScoped bool
	// MetadataOnly forces reads of this resource to return object metadata only —
	// never the object body. Set it on resources whose payload is sensitive (a
	// ConfigMap's data, and — by rule — a Secret's).
	MetadataOnly    bool
	RequireApproval bool
	Labels          []string
	Taints          []string
}

func (p Permission) allowsNamespace(ns string) bool {
	for _, allowed := range p.Namespaces {
		if allowed == "*" || allowed == ns {
			return true
		}
	}
	return false
}

// Client issues bounded single-object GET requests to one API server, paced by a
// rate limiter. The zero value is unusable; build one with NewClient.
type Client struct {
	access   Access
	http     *http.Client
	limiter  *rateLimiter
	timeout  time.Duration
	maxBytes int64
}

// Options configures a Client's bounds and pacing.
type Options struct {
	Timeout          time.Duration
	MaxResponseBytes int64
	RequestsPerSec   float64
	Burst            int
}

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.MaxResponseBytes <= 0 {
		o.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if o.RequestsPerSec <= 0 {
		o.RequestsPerSec = DefaultRequestsPerSec
	}
	if o.Burst <= 0 {
		o.Burst = DefaultBurst
	}
	return o
}

// NewClient builds a Client for the given API server access with the given
// bounds. It fails if the cluster CA is not valid PEM.
func NewClient(a Access, opts Options) (*Client, error) {
	opts = opts.withDefaults()
	transport, err := tlsTransport(a.caPEM, opts.Timeout)
	if err != nil {
		return nil, err
	}
	return &Client{
		access:   a,
		http:     &http.Client{Timeout: opts.Timeout, Transport: transport},
		limiter:  newRateLimiter(opts.RequestsPerSec, opts.Burst),
		timeout:  opts.Timeout,
		maxBytes: opts.MaxResponseBytes,
	}, nil
}

// errResponseTooLarge signals the API server returned more than the byte bound;
// the handler turns it into a hint rather than truncating JSON into something
// unparseable.
type errResponseTooLarge struct{ limit int64 }

func (e errResponseTooLarge) Error() string {
	return fmt.Sprintf("response exceeds %d bytes; request metadata_only for a lighter read", e.limit)
}

// get performs one paced GET. It waits on the rate limiter, attaches the current
// bearer token, reads a bounded body, and — on a 429/503 with Retry-After —
// pushes the whole grant into a cooldown so the next call waits. HTTP status
// codes come back in the Response for the handler to classify; only transport,
// context, and over-bound-body conditions are returned as errors.
func (c *Client) get(ctx context.Context, path string, query url.Values, accept string) (Response, error) {
	if err := c.limiter.wait(ctx); err != nil {
		return Response{}, err
	}
	token, err := c.access.tokens.token()
	if err != nil {
		return Response{}, err
	}
	target := c.access.endpoint + path
	if encoded := query.Encode(); encoded != "" {
		target += "?" + encoded
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Response{}, fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", accept)
	request.Header.Set("User-Agent", userAgent)

	response, err := c.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return Response{}, ctx.Err()
		}
		return Response{}, err
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable {
		// Server push-back: park the whole grant for the requested cooldown (capped).
		if d := retryAfter(response.Header); d > 0 {
			if d > maxRetryAfter {
				d = maxRetryAfter
			}
			c.limiter.backoff(d)
		}
	}

	body, err := readBounded(response.Body, c.maxBytes)
	if err != nil {
		return Response{}, err
	}
	return Response{Status: response.StatusCode, Body: body}, nil
}

// readBounded reads up to maxBytes, refusing (rather than truncating) a body that
// overflows so the returned JSON is never a mangled fragment.
func readBounded(reader io.Reader, maxBytes int64) (json.RawMessage, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, errResponseTooLarge{limit: maxBytes}
	}
	return json.RawMessage(data), nil
}

// retryAfter reads a Retry-After header in either its delta-seconds or HTTP-date
// form, returning the delay to wait (zero if absent or already past).
func retryAfter(header http.Header) time.Duration {
	value := strings.TrimSpace(header.Get("Retry-After"))
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds < 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		if d := time.Until(when); d > 0 {
			return d
		}
	}
	return 0
}

// Handler adapts the read Client to the builtin dispatcher, enforcing the grant's
// resource allowlist, per-resource flow policy, and approval before any request.
type Handler struct {
	Name string
	// CredentialLabel names the API credential (its keyed fingerprint, never its
	// value) so the journal records which service account read, stamped on every
	// result.
	CredentialLabel string
	Client          *Client
	// Resources is the allowlist; a linear scan matches a request's
	// (group, version, resource) — grants carry few resource types.
	Resources []Permission
}

func (h Handler) Handles(name string) bool { return name == h.Name }

// DispatchCall validates a get against the allowlist and flow policy, paces it,
// and stamps the result's provenance.
func (h Handler) DispatchCall(ctx context.Context, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if h.Client == nil {
		return sys.FailCode(sys.ErrnoInternal, "kubernetes client is not configured"), nil
	}
	var request Request
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", h.Name, err)), nil
	}
	verb, err := operationVerb(request.Operation)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
	}
	if err := validateIdentity(&request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
	}
	permission, err := h.match(request.Group, request.Version, request.Resource)
	if err != nil {
		return sys.FailCode(sys.ErrnoDenied, err.Error()), nil
	}
	if !permission.Verbs[verb] {
		return sys.FailCode(sys.ErrnoDenied, fmt.Sprintf("%s is not granted on %s", verb, resourceLabel(permission))), nil
	}

	// Sink guard: refuse before the read if the run has observed a label this
	// resource forbids. (Reads have no egress, but a grant may still bar tainted
	// data from steering which object is fetched.)
	if blocked := sys.BlockedBy(sys.Taint(ctx), permission.Taints); len(blocked) > 0 {
		return sys.FailCode(sys.ErrnoDenied, fmt.Sprintf(
			"flow policy: this run has observed %v, which may not flow into a kubernetes get", blocked)), nil
	}

	prepared, err := h.prepare(request, permission)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
	}

	if permission.RequireApproval && auth.Decision != sys.Approved {
		return sys.Yield(fmt.Sprintf("Approve kubernetes %s", prepared.summary)), nil
	}

	labels := append(append([]string(nil), permission.Labels...), h.credentialLabels()...)

	response, err := h.Client.get(ctx, prepared.path, prepared.query, prepared.accept)
	if err != nil {
		if ctx.Err() != nil {
			return sys.SyscallResult{}, ctx.Err()
		}
		var tooLarge errResponseTooLarge
		if errors.As(err, &tooLarge) {
			return sys.FailCode(sys.ErrnoInvalidArgs, tooLarge.Error()).WithLabels(labels...), nil
		}
		// A failed read still touched a labeled source: taint the run as if the
		// read happened, closing an error-channel launder.
		return sys.FailCode(sys.ErrnoTransient, err.Error()).WithLabels(labels...), nil
	}
	return classify(response, prepared.summary).WithLabels(labels...), nil
}

// prepared is a request reduced to the concrete HTTP shape the client executes.
type prepared struct {
	path    string
	query   url.Values
	accept  string
	summary string // human-facing, for approval prompts
}

// prepare turns a validated request plus its matched permission into the GET to
// perform. The path is built from the permission's own group/version/resource
// (trusted config), with only the validated namespace/name from the guest, and
// the read is always served from the API server's watch cache.
func (h Handler) prepare(request Request, permission Permission) (prepared, error) {
	namespace, err := h.resolveNamespace(request, permission)
	if err != nil {
		return prepared{}, err
	}
	if request.Name == "" {
		return prepared{}, fmt.Errorf("get requires a name")
	}
	query := url.Values{}
	// Serve from the API server's watch cache, never a quorum read of etcd — the
	// driver has no path that touches the datastore directly.
	query.Set("resourceVersion", "0")
	metadataOnly := permission.MetadataOnly || (request.MetadataOnly != nil && *request.MetadataOnly)

	path := resourcePath(permission.Group, permission.Version, permission.Resource, namespace, request.Name)
	return prepared{
		path:    path,
		query:   query,
		accept:  acceptHeader(metadataOnly),
		summary: summarize(permission, namespace, request.Name),
	}, nil
}

// resolveNamespace determines and authorizes the namespace: a cluster-scoped
// resource takes none; a namespaced get needs a concrete allowed namespace.
func (h Handler) resolveNamespace(request Request, permission Permission) (string, error) {
	if permission.ClusterScoped {
		if request.Namespace != "" {
			return "", fmt.Errorf("%s is cluster-scoped; do not pass a namespace", resourceLabel(permission))
		}
		return "", nil
	}
	if request.Namespace == "" {
		return "", fmt.Errorf("get on %s requires a namespace", resourceLabel(permission))
	}
	if !permission.allowsNamespace(request.Namespace) {
		return "", fmt.Errorf("namespace %q is not granted for %s", request.Namespace, resourceLabel(permission))
	}
	return request.Namespace, nil
}

// match finds the allowlist entry for a request's resource identity. Version may
// be omitted when the resource is granted at exactly one version.
func (h Handler) match(group, version, resource string) (Permission, error) {
	var candidates []Permission
	for _, permission := range h.Resources {
		if permission.Group == group && permission.Resource == resource {
			candidates = append(candidates, permission)
		}
	}
	if len(candidates) == 0 {
		return Permission{}, fmt.Errorf("resource %q (group %q) is not granted", resource, group)
	}
	if version == "" {
		if len(candidates) == 1 {
			return candidates[0], nil
		}
		return Permission{}, fmt.Errorf("resource %q is granted at multiple versions; specify one", resource)
	}
	for _, permission := range candidates {
		if permission.Version == version {
			return permission, nil
		}
	}
	return Permission{}, fmt.Errorf("resource %q at version %q is not granted", resource, version)
}

func (h Handler) credentialLabels() []string {
	if h.CredentialLabel == "" {
		return nil
	}
	return []string{h.CredentialLabel}
}

// operationVerb maps the call's operation discriminator to a verb. get is the
// only operation this driver implements; the switch is where a future operation
// (list, …) is admitted, at which point the per-resource Verbs allowlist already
// gates it.
func operationVerb(operation string) (string, error) {
	switch operation {
	case VerbGet:
		return VerbGet, nil
	case "":
		return "", fmt.Errorf("operation is required")
	default:
		return "", fmt.Errorf("unknown operation %q (only get is supported)", operation)
	}
}

// validateIdentity checks every guest-supplied identity field against its strict
// pattern, before any of it is used to look up a permission or build a path.
func validateIdentity(request *Request) error {
	request.Group = strings.TrimSpace(request.Group)
	request.Version = strings.TrimSpace(request.Version)
	request.Resource = strings.TrimSpace(request.Resource)
	request.Namespace = strings.TrimSpace(request.Namespace)
	request.Name = strings.TrimSpace(request.Name)
	if err := validateGroup(request.Group); err != nil {
		return err
	}
	if request.Version != "" {
		if err := validateVersion(request.Version); err != nil {
			return err
		}
	}
	if err := validateResource(request.Resource); err != nil {
		return err
	}
	if request.Namespace != "" {
		if err := validateNamespace(request.Namespace); err != nil {
			return err
		}
	}
	if request.Name != "" {
		if err := validateName(request.Name); err != nil {
			return err
		}
	}
	return nil
}

// resourcePath builds the REST path from trusted (config) group/version/resource
// and validated namespace/name. Namespace and name are additionally
// percent-escaped as defense in depth even though they are pattern-validated.
func resourcePath(group, version, resource, namespace, name string) string {
	var b strings.Builder
	if group == "" {
		b.WriteString("/api/")
		b.WriteString(version)
	} else {
		b.WriteString("/apis/")
		b.WriteString(group)
		b.WriteString("/")
		b.WriteString(version)
	}
	if namespace != "" {
		b.WriteString("/namespaces/")
		b.WriteString(url.PathEscape(namespace))
	}
	b.WriteString("/")
	b.WriteString(resource)
	if name != "" {
		b.WriteString("/")
		b.WriteString(url.PathEscape(name))
	}
	return b.String()
}

// acceptHeader chooses the response representation. A metadata-only read returns
// PartialObjectMetadata — names, labels, and timestamps but not the object body.
func acceptHeader(metadataOnly bool) string {
	if metadataOnly {
		return "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1"
	}
	return "application/json"
}

// classify maps an API server HTTP status to a syscall result: 2xx returns the
// body, and each error class maps to the errno a program branches on. The
// (bounded) Status body is surfaced so the model sees the server's own message.
func classify(response Response, summary string) sys.SyscallResult {
	switch {
	case response.Status >= 200 && response.Status < 300:
		result, err := json.Marshal(response)
		if err != nil {
			return sys.FailCode(sys.ErrnoInternal, fmt.Sprintf("encode get result: %v", err))
		}
		return sys.Result(result)
	case response.Status == http.StatusNotFound:
		return sys.FailCode(sys.ErrnoNotFound, statusMessage(response, summary))
	case response.Status == http.StatusUnauthorized, response.Status == http.StatusForbidden:
		return sys.FailCode(sys.ErrnoDenied, statusMessage(response, summary))
	case response.Status == http.StatusTooManyRequests, response.Status >= 500:
		return sys.FailCode(sys.ErrnoTransient, statusMessage(response, summary))
	default:
		return sys.FailCode(sys.ErrnoInvalidArgs, statusMessage(response, summary))
	}
}

// statusMessage extracts the message from a Kubernetes Status object, falling
// back to the request summary and code.
func statusMessage(response Response, summary string) string {
	var status struct {
		Message string `json:"message"`
		Reason  string `json:"reason"`
	}
	_ = json.Unmarshal(response.Body, &status)
	if status.Message != "" {
		return fmt.Sprintf("%s (%d): %s", summary, response.Status, status.Message)
	}
	return fmt.Sprintf("%s: server returned %d", summary, response.Status)
}

func resourceLabel(permission Permission) string {
	if permission.Group == "" {
		return permission.Resource
	}
	return permission.Resource + "." + permission.Group
}

func summarize(permission Permission, namespace, name string) string {
	target := resourceLabel(permission)
	if namespace != "" {
		target = namespace + "/" + target
	}
	return "get " + target + "/" + name
}
