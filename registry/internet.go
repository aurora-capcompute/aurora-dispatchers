package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/internet"
	"github.com/aurora-capcompute/capcompute/sys"
)

// InternetPermission is one allowlisted class of request the grant may make:
// the methods (an HTTP method list, or ["*"] for any) permitted against a
// domain (a host, or "*" for any). The permissions together are the policy that
// constrains every request the program can make through this grant.
type InternetPermission struct {
	Methods []string `json:"methods"`
	Domain  string   `json:"domain"`
}

type InternetSettings struct {
	Permissions      []InternetPermission `json:"permissions"`
	TimeoutMS        int64                `json:"timeout_ms,omitempty"`
	MaxResponseBytes int64                `json:"max_response_bytes,omitempty"`
	MaxRequestBytes  int64                `json:"max_request_bytes,omitempty"`
	RequireApproval  bool                 `json:"require_approval,omitempty"`
}

type InternetRegistration struct{}

func (InternetRegistration) Matches(syscall string) bool { return syscall == "core.internet" }

func (InternetRegistration) Normalize(_ string, raw json.RawMessage) (json.RawMessage, error) {
	settings, _, err := parseInternetSettings(raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(settings)
}

func (InternetRegistration) Configure(_ context.Context, raw json.RawMessage, _ Services, config *builtin.Config) error {
	settings, policy, err := parseInternetSettings(raw)
	if err != nil {
		return err
	}
	client := internet.NewConfiguredClient(
		policy,
		time.Duration(settings.TimeoutMS)*time.Millisecond,
		settings.MaxResponseBytes,
		settings.MaxRequestBytes,
	)
	config.Handlers = append(config.Handlers, builtin.InternetHandler{
		Name:            internet.Capability,
		Client:          client,
		RequireApproval: settings.RequireApproval,
	})
	config.Capabilities = append(config.Capabilities, sys.Capability{
		Name:        internet.Capability,
		Description: internetDescription(settings.Permissions),
		InputSchema: json.RawMessage(`{"type":"object","properties":{"method":{"type":"string"},"url":{"type":"string","format":"uri"},"headers":{"type":"object","additionalProperties":{"type":"string"}},"body":{"type":"string"}},"required":["method","url"],"additionalProperties":false}`),
	})
	return nil
}

// parseInternetSettings validates and canonicalizes a core.internet grant's
// settings and derives the request policy from its permissions — the single
// parse Normalize (which marshals it) and Configure (which builds from it)
// share.
func parseInternetSettings(raw json.RawMessage) (InternetSettings, internet.Policy, error) {
	settings := InternetSettings{
		TimeoutMS:        int64(internet.DefaultTimeout / time.Millisecond),
		MaxResponseBytes: internet.DefaultMaxResponseBytes,
		MaxRequestBytes:  internet.DefaultMaxRequestBytes,
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &settings); err != nil {
			return InternetSettings{}, internet.Policy{}, err
		}
	}
	if len(settings.Permissions) == 0 {
		return InternetSettings{}, internet.Policy{}, fmt.Errorf("permissions must contain at least one {methods, domain}")
	}

	var rules []internet.Rule
	for i := range settings.Permissions {
		permission := &settings.Permissions[i]
		domain := strings.TrimSpace(permission.Domain)
		if domain == "" {
			return InternetSettings{}, internet.Policy{}, fmt.Errorf("permission %d: domain is empty", i)
		}
		methods := canonicalMethods(permission.Methods)
		if len(methods) == 0 {
			return InternetSettings{}, internet.Policy{}, fmt.Errorf("permission %d: methods must contain at least one HTTP method (or \"*\")", i)
		}
		for _, method := range methods {
			rule, err := internet.NewRule(method, domain)
			if err != nil {
				return InternetSettings{}, internet.Policy{}, fmt.Errorf("permission %d: %w", i, err)
			}
			rules = append(rules, rule)
		}
		*permission = InternetPermission{Methods: methods, Domain: domain}
	}
	if settings.TimeoutMS <= 0 {
		return InternetSettings{}, internet.Policy{}, fmt.Errorf("timeout_ms must be positive")
	}
	if settings.MaxResponseBytes <= 0 {
		return InternetSettings{}, internet.Policy{}, fmt.Errorf("max_response_bytes must be positive")
	}
	if settings.MaxRequestBytes <= 0 {
		return InternetSettings{}, internet.Policy{}, fmt.Errorf("max_request_bytes must be positive")
	}
	return settings, internet.NewPolicy(rules...), nil
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
