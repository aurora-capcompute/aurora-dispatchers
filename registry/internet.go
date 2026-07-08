package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/internet"
	"github.com/aurora-capcompute/capcompute/sys"
)

// InternetPermission is one entry of a core.internet grant's `capabilities`
// list: the methods (an HTTP method list, or ["*"] for any) permitted against a
// domain (a host, or "*" for any), the request's data-flow policy, and whether
// it needs human approval. The permissions together are the allowlist that
// constrains every request the program can make through this grant.
type InternetPermission struct {
	Methods         []string `json:"methods"`
	Domain          string   `json:"domain"`
	RequireApproval *bool    `json:"require_approval,omitempty"`
	FlowPolicy
}

// internetConfig is a core.internet grant's driver configuration: its
// capabilities (the allowlist + per-request flow) and the response/request
// bounds. The HTTP method is the ADT discriminator of the single net capability.
type internetConfig struct {
	Capabilities     []InternetPermission `json:"capabilities,omitempty"`
	TimeoutMS        int64                `json:"timeout_ms,omitempty"`
	MaxResponseBytes int64                `json:"max_response_bytes,omitempty"`
	MaxRequestBytes  int64                `json:"max_request_bytes,omitempty"`
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

func (InternetRegistration) Configure(_ context.Context, raw json.RawMessage, _ Services, out *builtin.Config) error {
	config, policy, err := parseInternetConfig(raw)
	if err != nil {
		return err
	}
	client := internet.NewConfiguredClient(
		policy,
		time.Duration(config.TimeoutMS)*time.Millisecond,
		config.MaxResponseBytes,
		config.MaxRequestBytes,
	)
	out.Handlers = append(out.Handlers, builtin.InternetHandler{
		Name:    internet.Capability,
		Methods: internetMethodPolicies(config.Capabilities),
		Client:  client,
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
		permission.Methods = methods
		permission.Domain = domain
		permission.FlowPolicy = flow
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

func internetDescription(permissions []InternetPermission) string {
	var b strings.Builder
	b.WriteString("Make an HTTP request (any method the grant allows) and read the bounded response. Allowed:")
	for i, permission := range permissions {
		if i > 0 {
			b.WriteString(";")
		}
		fmt.Fprintf(&b, " %s → %s", strings.Join(permission.Methods, "/"), permission.Domain)
	}
	b.WriteString(".")
	return b.String()
}
