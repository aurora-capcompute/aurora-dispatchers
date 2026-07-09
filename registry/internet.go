package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/internet"
	"github.com/aurora-capcompute/capcompute/sys"
)

var headerNamePattern = regexp.MustCompile(`^[!#$%&'*+\-.^_` + "`" + `|~0-9A-Za-z]+$`)

// InternetPermission is one entry of a core.internet grant's `capabilities`
// list: the methods (an HTTP method list, or ["*"] for any) permitted against a
// domain (a host, or "*" for any), the request's data-flow policy, and whether
// it needs human approval. The permissions together are the allowlist that
// constrains every request the program can make through this grant.
type InternetPermission struct {
	Methods         []string `json:"methods"`
	Domain          string   `json:"domain"`
	RequireApproval *bool    `json:"require_approval,omitempty"`
	// Description is an author-supplied usage note for this origin — how to call
	// it, which paths and body shape it expects — woven into the published
	// capability's description (the model's tool doc) beside the origin's methods
	// and domain. It is manifest-authored trusted policy, never guest- or
	// network-supplied; do not put a secret value here, as it is persisted and
	// shown to the model.
	Description string `json:"description,omitempty"`
	// InjectHeaders attaches host-held request headers (e.g. an Authorization
	// bearer token) to requests this permission allows. Because it carries a
	// credential, a permission that injects one must be a specific https host
	// (never domain "*", never plain http off loopback), and the guest can
	// neither supply nor read the value. Keyed by header name.
	InjectHeaders map[string]HeaderInjection `json:"inject_headers,omitempty"`
	FlowPolicy
}

// HeaderInjection is one host-attached header value: drawn from a host-held
// secret (Secret ref, recommended) or a literal (Value, soft-deprecated), with
// an optional Prefix such as "Bearer ". Exactly one of Secret or Value is set.
type HeaderInjection struct {
	Secret string `json:"secret,omitempty"`
	Value  string `json:"value,omitempty"`
	Prefix string `json:"prefix,omitempty"`
}

// internetConfig is a core.internet grant's driver configuration: its
// capabilities (the allowlist + per-request flow) and the response/request
// bounds. The HTTP method is the ADT discriminator of the single net capability.
type internetConfig struct {
	Capabilities     []InternetPermission `json:"capabilities,omitempty"`
	TimeoutMS        int64                `json:"timeout_ms,omitempty"`
	MaxResponseBytes int64                `json:"max_response_bytes,omitempty"`
	MaxRequestBytes  int64                `json:"max_request_bytes,omitempty"`
	// AllowPrivateNetwork opts this grant out of the SSRF guard, permitting
	// requests to loopback/private/link-local addresses. Off by default: a grant
	// reaches internal services only when the manifest says so explicitly.
	AllowPrivateNetwork bool `json:"allow_private_network,omitempty"`
}

// internetRequestSchema is the single flat schema every core.internet call
// carries; `method` is the discriminator the allowlist and flow policy read.
var internetRequestSchema = json.RawMessage(`{"type":"object","properties":{"method":{"type":"string"},"url":{"type":"string","format":"uri"},"headers":{"type":"object","additionalProperties":{"type":"string"}},"body":{"type":"string"}},"required":["method","url"],"additionalProperties":false}`)

type InternetRegistration struct{}

func (InternetRegistration) Matches(syscall string) bool { return syscall == internet.Capability }

func (InternetRegistration) Normalize(_ string, raw json.RawMessage) (json.RawMessage, error) {
	config, _, err := parseInternetConfig(raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(config)
}

func (InternetRegistration) Configure(_ context.Context, raw json.RawMessage, services Services, out *builtin.Config) error {
	config, policy, err := parseInternetConfig(raw)
	if err != nil {
		return err
	}
	// Resolve credential injections host-side. A missing secret fails here — at
	// driver build / activation — never silently at request time.
	injections, err := buildInjections(config.Capabilities, services)
	if err != nil {
		return err
	}
	client := internet.NewConfiguredClient(
		policy,
		time.Duration(config.TimeoutMS)*time.Millisecond,
		config.MaxResponseBytes,
		config.MaxRequestBytes,
	)
	// SSRF guard on unless the grant explicitly opted into private networks.
	client.AllowPrivateNetwork = config.AllowPrivateNetwork
	out.Handlers = append(out.Handlers, builtin.InternetHandler{
		Name:       internet.Capability,
		Methods:    internetMethodPolicies(config.Capabilities),
		Client:     client,
		Injections: injections,
	})
	out.Capabilities = append(out.Capabilities, sys.Capability{
		Name:        internet.Capability,
		Description: internetDescription(config.Capabilities),
		InputSchema: internetRequestSchema,
	})
	return nil
}

// parseInternetConfig validates and canonicalizes a core.internet grant's
// config and derives the request allowlist from its capabilities — the single
// parse Normalize (which marshals it) and Configure (which builds from it) share.
func parseInternetConfig(raw json.RawMessage) (internetConfig, internet.Policy, error) {
	config := internetConfig{
		TimeoutMS:        int64(internet.DefaultTimeout / time.Millisecond),
		MaxResponseBytes: internet.DefaultMaxResponseBytes,
		MaxRequestBytes:  internet.DefaultMaxRequestBytes,
	}
	if len(raw) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config); err != nil {
			return internetConfig{}, internet.Policy{}, err
		}
	}
	if len(config.Capabilities) == 0 {
		return internetConfig{}, internet.Policy{}, fmt.Errorf("capabilities must contain at least one {methods, domain}")
	}

	var rules []internet.Rule
	for i := range config.Capabilities {
		permission := &config.Capabilities[i]
		domain := strings.TrimSpace(permission.Domain)
		if domain == "" {
			return internetConfig{}, internet.Policy{}, fmt.Errorf("permission %d: domain is empty", i)
		}
		methods := canonicalMethods(permission.Methods)
		if len(methods) == 0 {
			return internetConfig{}, internet.Policy{}, fmt.Errorf("permission %d: methods must contain at least one HTTP method (or \"*\")", i)
		}
		for _, method := range methods {
			rule, err := internet.NewRule(method, domain)
			if err != nil {
				return internetConfig{}, internet.Policy{}, fmt.Errorf("permission %d: %w", i, err)
			}
			rules = append(rules, rule)
		}
		flow, err := permission.FlowPolicy.Normalized()
		if err != nil {
			return internetConfig{}, internet.Policy{}, fmt.Errorf("permission %d: %w", i, err)
		}
		description, err := sanitizeDescription(permission.Description)
		if err != nil {
			return internetConfig{}, internet.Policy{}, fmt.Errorf("permission %d: %w", i, err)
		}
		permission.Methods = methods
		permission.Domain = domain
		permission.Description = description
		permission.FlowPolicy = flow
		if len(permission.InjectHeaders) > 0 {
			if err := validateInjection(domain, permission.InjectHeaders); err != nil {
				return internetConfig{}, internet.Policy{}, fmt.Errorf("permission %d: %w", i, err)
			}
		}
	}
	if config.TimeoutMS <= 0 {
		return internetConfig{}, internet.Policy{}, fmt.Errorf("timeout_ms must be positive")
	}
	if config.MaxResponseBytes <= 0 {
		return internetConfig{}, internet.Policy{}, fmt.Errorf("max_response_bytes must be positive")
	}
	if config.MaxRequestBytes <= 0 {
		return internetConfig{}, internet.Policy{}, fmt.Errorf("max_request_bytes must be positive")
	}
	return config, internet.NewPolicy(rules...), nil
}

// validateInjection enforces the credential-safety rules on a permission's
// injected headers: the origin must be a specific host (never "*") and https
// (loopback may use http, where there is no wire to sniff), each header name
// must be a valid, non-transport-controlled name, and each injection must name
// exactly one source. Structural only — resolution happens in Configure.
func validateInjection(domain string, headers map[string]HeaderInjection) error {
	origin, err := internet.NewRule(internet.AnyMethod, domain)
	if err != nil {
		return err
	}
	if origin.AnyHost {
		return fmt.Errorf(`inject_headers cannot be used with domain "*": a credential must be bound to a specific host`)
	}
	if origin.Scheme == "http" && !isLoopbackHost(origin.Host) {
		return fmt.Errorf("a credential-injecting permission must use https (host %q is plain http)", origin.Host)
	}
	for name, injection := range headers {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if canonical == "" || !headerNamePattern.MatchString(canonical) {
			return fmt.Errorf("invalid inject header name %q", name)
		}
		switch canonical {
		case "Host", "Content-Length":
			return fmt.Errorf("header %q cannot be injected", canonical)
		}
		if (strings.TrimSpace(injection.Secret) != "") == (injection.Value != "") {
			return fmt.Errorf(`inject_headers[%q]: set exactly one of "secret" or "value"`, name)
		}
	}
	return nil
}

// buildInjections resolves each credential-injecting permission into a host-held
// header set the internet handler attaches at dispatch. Called only from
// Configure (activation), so a missing/unknown secret fails the driver build —
// recorded there — rather than silently at request time. The resolved value is
// never persisted (Normalize keeps only the reference).
func buildInjections(permissions []InternetPermission, services Services) ([]builtin.CredentialInjection, error) {
	var out []builtin.CredentialInjection
	for i := range permissions {
		permission := permissions[i]
		if len(permission.InjectHeaders) == 0 {
			continue
		}
		origin, err := internet.NewRule(internet.AnyMethod, permission.Domain)
		if err != nil {
			return nil, fmt.Errorf("permission %d: %w", i, err)
		}
		headers := make(map[string]string, len(permission.InjectHeaders))
		var labels []string
		for name, injection := range permission.InjectHeaders {
			canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
			var secret Secret
			if ref := strings.TrimSpace(injection.Secret); ref != "" {
				secret = SecretRef(ref)
			} else {
				secret = LiteralSecret(injection.Value)
			}
			value, err := secret.Resolve(services.Secrets)
			if err != nil {
				return nil, fmt.Errorf("permission %d header %q: %w", i, canonical, err)
			}
			headers[canonical] = injection.Prefix + value
			credName := secret.Ref()
			if credName == "" {
				credName = "inline"
			}
			labels = append(labels, "credential:"+credName+"@"+CredentialFingerprint(services.AuditKey, value))
		}
		out = append(out, builtin.CredentialInjection{
			Methods: permission.Methods,
			Host:    strings.ToLower(origin.Host),
			Headers: headers,
			Labels:  labels,
		})
	}
	return out, nil
}

// internetMethodPolicies aggregates the grant's per-permission flow and approval
// into a per-method policy the handler reads by the request's method ("*" is the
// wildcard bucket, merged with the specific method at dispatch).
func internetMethodPolicies(permissions []InternetPermission) map[string]builtin.InternetMethodPolicy {
	methods := make(map[string]builtin.InternetMethodPolicy)
	for _, permission := range permissions {
		approval := permission.RequireApproval != nil && *permission.RequireApproval
		for _, method := range permission.Methods {
			existing := methods[method]
			methods[method] = builtin.InternetMethodPolicy{
				RequireApproval: existing.RequireApproval || approval,
				Labels:          builtin.UnionLabels(existing.Labels, permission.Labels),
				Taints:          builtin.UnionLabels(existing.Taints, permission.Taints),
			}
		}
	}
	return methods
}

// canonicalMethods uppercases and de-duplicates a permission's methods,
// defaulting an empty list to GET.
func canonicalMethods(methods []string) []string {
	if len(methods) == 0 {
		return []string{"GET"}
	}
	seen := make(map[string]struct{}, len(methods))
	out := make([]string, 0, len(methods))
	for _, method := range methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "" {
			continue
		}
		if _, dup := seen[method]; dup {
			continue
		}
		seen[method] = struct{}{}
		out = append(out, method)
	}
	return out
}

// maxPermissionDescriptionLen bounds an author-supplied usage note so a manifest
// cannot bloat the model's tool prompt without limit.
const maxPermissionDescriptionLen = 2000

// sanitizeDescription trims and bounds an author-supplied usage note. The text
// is manifest-authored (trusted policy, never guest- or network-supplied), but
// it lands verbatim in the model's tool prompt, so it is length-bounded and
// refused if it carries a control character that would corrupt that prompt
// (newline and tab, which format it, are allowed).
func sanitizeDescription(raw string) (string, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return "", nil
	}
	if len(text) > maxPermissionDescriptionLen {
		return "", fmt.Errorf("description is %d bytes, over the %d-byte limit", len(text), maxPermissionDescriptionLen)
	}
	for _, r := range text {
		if r == '\n' || r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("description contains a control character %q", r)
		}
	}
	return text, nil
}

// internetDescription composes the published capability's description — the
// model's tool doc — from each permitted origin: its methods, its domain, and
// the author's usage note when supplied.
func internetDescription(permissions []InternetPermission) string {
	var b strings.Builder
	b.WriteString("Make an HTTP request (any method the grant allows) and read the bounded response. Allowed origins:")
	for _, permission := range permissions {
		fmt.Fprintf(&b, "\n- %s → %s", strings.Join(permission.Methods, "/"), permission.Domain)
		if permission.Description != "" {
			b.WriteString(": ")
			b.WriteString(permission.Description)
		}
	}
	return b.String()
}
