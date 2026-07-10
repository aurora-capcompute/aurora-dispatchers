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

// Permission is one flattened (verb, resource-rule) grant: the verb it enables
// and the resource it covers, plus scope and flow policy. It is host-authored
// trusted policy. Group and Resource may be "*", a wildcard matching any: a
// concrete rule pins the path's group/version/resource, while a wildcard rule
// lets the guest name them (still strictly validated).
type Permission struct {
	// Verb is the operation this permission grants (get today).
	Verb string
	// Group is the API group, or "*" for any. Version pins a concrete resource's
	// version; it is empty for a wildcard resource (the guest supplies it).
	Group    string
	Version  string
	Resource string // "*" = any resource
	// Namespaces are the allowed namespaces; "*" means any. The guest still names
	// a concrete namespace on each get — the wildcard only removes the
	// restriction on which one. Ignored when ClusterScoped.
	Namespaces []string
	// ClusterScoped marks a non-namespaced resource (nodes, namespaces,
	// persistentvolumes). Its reads carry no namespace.
	ClusterScoped bool
	// MetadataOnly forces reads matched by this rule to return object metadata
	// only — never the object body.
	MetadataOnly    bool
	RequireApproval bool
	Labels          []string
	Taints          []string
}

// matchesResource reports whether this permission covers a request's group and
// resource, honoring "*" wildcards on either.
func (p Permission) matchesResource(group, resource string) bool {
	groupOK := p.Group == "*" || p.Group == group
	resourceOK := p.Resource == "*" || p.Resource == resource
	return groupOK && resourceOK
}

// authorizesNamespace reports whether a request's namespace is allowed: a
// cluster-scoped rule takes none, a namespaced rule needs one it allows.
func (p Permission) authorizesNamespace(ns string) bool {
	if p.ClusterScoped {
		return ns == ""
	}
	if ns == "" {
		return false
	}
	for _, allowed := range p.Namespaces {
		if allowed == "*" || allowed == ns {
			return true
		}
	}
	return false
}

// specificity ranks a matching permission so the most specific rule (concrete
// resource, concrete group) wins when several cover the same request.
func (p Permission) specificity() int {
	score := 0
	if p.Resource != "*" {
		score += 2
	}
	if p.Group != "*" {
		score++
	}
	return score
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
	permission, err := h.authorize(verb, request)
	if err != nil {
		return sys.FailCode(sys.ErrnoDenied, err.Error()), nil
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

// authorize finds the allowlist entry that permits a request: the most specific
// rule (concrete over wildcard) whose verb, resource, and namespace all admit
// it. The denial names why — the resource is not granted, or the namespace is.
func (h Handler) authorize(verb string, r Request) (Permission, error) {
	best := Permission{}
	bestScore := -1
	resourceMatched := false
	for _, p := range h.Resources {
		if p.Verb != verb || !p.matchesResource(r.Group, r.Resource) {
			continue
		}
		resourceMatched = true
		if !p.authorizesNamespace(r.Namespace) {
			continue
		}
		if score := p.specificity(); score > bestScore {
			best, bestScore = p, score
		}
	}
	if bestScore >= 0 {
		return best, nil
	}
	target := r.Resource
	if r.Group != "" {
		target += "." + r.Group
	}
	switch {
	case !resourceMatched:
		return Permission{}, fmt.Errorf("%s of %q is not granted", verb, target)
	case r.Namespace == "":
		return Permission{}, fmt.Errorf("%s of %q requires an allowed namespace", verb, target)
	default:
		return Permission{}, fmt.Errorf("%s of %q in namespace %q is not granted", verb, target, r.Namespace)
	}
}

// prepare turns a validated request plus its authorizing permission into the GET
// to perform. A concrete rule pins group/version/resource; a wildcard rule uses
// the guest's (strictly validated) values. The read is always served from the
// API server's watch cache, and core Secrets are held metadata-only however they
// were matched — the floor a wildcard rule cannot lower.
func (h Handler) prepare(request Request, permission Permission) (prepared, error) {
	if request.Name == "" {
		return prepared{}, fmt.Errorf("get requires a name")
	}
	group := permission.Group
	if group == "*" {
		group = request.Group
	}
	resource := permission.Resource
	if resource == "*" {
		resource = request.Resource
	}
	version := permission.Version
	if permission.Resource == "*" || permission.Group == "*" || version == "" {
		// The identity is (partly) guest-chosen, so a concrete version cannot be
		// pinned from config; take the guest's, defaulting to v1.
		version = request.Version
		if version == "" {
			version = "v1"
		}
	}
	namespace := ""
	if !permission.ClusterScoped {
		namespace = request.Namespace
	}

	metadataOnly := permission.MetadataOnly || (request.MetadataOnly != nil && *request.MetadataOnly)
	// The Secret-data floor holds regardless of how the read was matched: a
	// wildcard rule that forgot metadata_only cannot be used to read Secret bodies.
	if group == "" && resource == "secrets" && !metadataOnly {
		return prepared{}, fmt.Errorf(`core "secrets" may only be read metadata-only`)
	}

	query := url.Values{}
	// Serve from the API server's watch cache, never a quorum read of etcd — the
	// driver has no path that touches the datastore directly.
	query.Set("resourceVersion", "0")
	return prepared{
		path:    resourcePath(group, version, resource, namespace, request.Name),
		query:   query,
		accept:  acceptHeader(metadataOnly),
		summary: summarize(group, resource, namespace, request.Name),
	}, nil
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

func summarize(group, resource, namespace, name string) string {
	target := resource
	if group != "" {
		target = resource + "." + group
	}
	if namespace != "" {
		target = namespace + "/" + target
	}
	return "get " + target + "/" + name
}
