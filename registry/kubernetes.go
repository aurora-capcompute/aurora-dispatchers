package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/k8s"
	"github.com/aurora-capcompute/capcompute/sys"
)

// KubernetesVerbGrant is one case of a core.kubernetes grant's `capabilities`
// ADT, discriminated by verb: the read verb it enables and the resources that
// verb may read. get is the only verb available today. Making the verb the
// discriminator groups an operation with the resources it applies to — the
// natural shape once more than one operation exists.
type KubernetesVerbGrant struct {
	Verb      string                   `json:"verb"`
	Resources []KubernetesResourceRule `json:"resources"`
}

// KubernetesResourceRule is one resource a verb grant covers. Each rule carries
// its own scope (namespaces / cluster-scoped), read shape (metadata_only),
// approval, and flow policy.
type KubernetesResourceRule struct {
	// Group is the API group ("" is the core group). Version pins the resource's
	// version (default v1).
	Group    string `json:"group,omitempty"`
	Version  string `json:"version,omitempty"`
	Resource string `json:"resource"`
	// Namespaces are the namespaces this rule may be read in; "*" means any.
	// Required for a namespaced rule, must be empty for a cluster-scoped one.
	Namespaces []string `json:"namespaces,omitempty"`
	// ClusterScoped marks a non-namespaced resource (nodes, namespaces,
	// persistentvolumes). Its reads carry no namespace.
	ClusterScoped bool `json:"cluster_scoped,omitempty"`
	// MetadataOnly forces reads matched by this rule to return only object
	// metadata — never the object body. (Core Secrets are metadata-only by rule,
	// re-enforced at request time as a hard floor.)
	MetadataOnly    bool  `json:"metadata_only,omitempty"`
	RequireApproval *bool `json:"require_approval,omitempty"`
	FlowPolicy
}

// kubernetesConfig is a core.kubernetes grant's driver configuration: the
// verb-discriminated allowlist, an optional explicit API-server override (else
// the pod's in-cluster service account is used), and the request bounds and
// pacing that keep the driver gentle on the API server.
type kubernetesConfig struct {
	Capabilities []KubernetesVerbGrant `json:"capabilities,omitempty"`
	// Endpoint/Token/CACert are the explicit-config override. When both Endpoint
	// and Token are set the driver talks to that API server; otherwise it uses
	// the in-cluster service account. A bearer Token must be a secret reference
	// (recommended) or a literal, resolved host-side and never shown to the guest.
	Endpoint string `json:"endpoint,omitempty"`
	Token    Secret `json:"token,omitempty"`
	CACert   string `json:"ca_cert,omitempty"`
	// TimeoutMS bounds each request; MaxResponseBytes bounds the body read.
	TimeoutMS        int64 `json:"timeout_ms,omitempty"`
	MaxResponseBytes int64 `json:"max_response_bytes,omitempty"`
	// RequestsPerSecond and Burst are the token-bucket rate limit — the ceiling
	// on how fast this grant may hit the API server.
	RequestsPerSecond float64 `json:"requests_per_second,omitempty"`
	Burst             int     `json:"burst,omitempty"`
}

// getOperationSchema is the guest-input schema a get call carries (minus the
// `operation` discriminator OperationBranch injects).
var getOperationSchema = json.RawMessage(`{"type":"object","properties":{"group":{"type":"string"},"version":{"type":"string"},"resource":{"type":"string","minLength":1},"namespace":{"type":"string"},"name":{"type":"string","minLength":1},"metadata_only":{"type":"boolean"}},"required":["resource","name"],"additionalProperties":false}`)

// KubernetesRegistration provides a read-only, rate-limited window onto a
// Kubernetes API server. It publishes core.kubernetes with a single operation —
// get one object by name — over an author-declared resource allowlist. There is
// no write path, and no list, selector, pagination, or etcd-quorum read: only a
// single-object read served from the API server's watch cache.
type KubernetesRegistration struct{}

func (KubernetesRegistration) Matches(syscall string) bool { return syscall == k8s.Capability }

func (KubernetesRegistration) Normalize(_ string, raw json.RawMessage) (json.RawMessage, error) {
	config, grants, err := parseKubernetesConfig(raw)
	if err != nil {
		return nil, err
	}
	config.Capabilities = grants
	return json.Marshal(config)
}

func (KubernetesRegistration) Configure(_ context.Context, raw json.RawMessage, services Services, out *builtin.Config) error {
	config, grants, err := parseKubernetesConfig(raw)
	if err != nil {
		return err
	}
	clusterAccess, credentialLabel, err := resolveKubernetesAccess(config, services)
	if err != nil {
		return err
	}
	client, err := k8s.NewClient(clusterAccess, k8s.Options{
		Timeout:          durationMS(config.TimeoutMS),
		MaxResponseBytes: config.MaxResponseBytes,
		RequestsPerSec:   config.RequestsPerSecond,
		Burst:            config.Burst,
	})
	if err != nil {
		return err
	}

	// Flatten each (verb, resource-rule) into one Permission the handler scans.
	var permissions []k8s.Permission
	verbsGranted := map[string]bool{}
	for _, grant := range grants {
		verbsGranted[grant.Verb] = true
		for _, rule := range grant.Resources {
			permissions = append(permissions, k8s.Permission{
				Verb:            grant.Verb,
				Group:           rule.Group,
				Version:         rule.Version,
				Resource:        rule.Resource,
				Namespaces:      rule.Namespaces,
				ClusterScoped:   rule.ClusterScoped,
				MetadataOnly:    rule.MetadataOnly,
				RequireApproval: rule.RequireApproval != nil && *rule.RequireApproval,
				Labels:          rule.Labels,
				Taints:          rule.Taints,
			})
		}
	}

	out.Handlers = append(out.Handlers, k8s.Handler{
		Name:            k8s.Capability,
		CredentialLabel: credentialLabel,
		Client:          client,
		Resources:       permissions,
	})

	// One guest-facing ADT branch per granted verb (get today).
	branches := make([]json.RawMessage, 0, len(verbsGranted))
	for _, verb := range []string{k8s.VerbGet} {
		if !verbsGranted[verb] {
			continue
		}
		branch, err := OperationBranch(verb, getOperationSchema)
		if err != nil {
			return err
		}
		branches = append(branches, branch)
	}
	out.Capabilities = append(out.Capabilities, sys.Capability{
		Name:        k8s.Capability,
		Description: kubernetesDescription(grants),
		InputSchema: OneOfSchema(branches),
	})
	return nil
}

// parseKubernetesConfig validates and canonicalizes a core.kubernetes grant's
// config — the single parse Normalize and Configure share. It rejects unknown
// fields, requires at least one verb grant, and normalizes each verb case and
// its resource rules.
func parseKubernetesConfig(raw json.RawMessage) (kubernetesConfig, []KubernetesVerbGrant, error) {
	var config kubernetesConfig
	if len(raw) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config); err != nil {
			return kubernetesConfig{}, nil, err
		}
	}
	if len(config.Capabilities) == 0 {
		return kubernetesConfig{}, nil, fmt.Errorf("capabilities must grant at least one verb")
	}
	seenVerb := make(map[string]struct{}, len(config.Capabilities))
	grants := make([]KubernetesVerbGrant, len(config.Capabilities))
	for i, grant := range config.Capabilities {
		normalized, err := normalizeVerbGrant(grant)
		if err != nil {
			return kubernetesConfig{}, nil, fmt.Errorf("capability %d: %w", i, err)
		}
		if _, dup := seenVerb[normalized.Verb]; dup {
			return kubernetesConfig{}, nil, fmt.Errorf("verb %q is granted more than once", normalized.Verb)
		}
		seenVerb[normalized.Verb] = struct{}{}
		grants[i] = normalized
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].Verb < grants[j].Verb })

	// An explicit endpoint and token must be given together, or neither (in-cluster).
	if (config.Endpoint != "") != !config.Token.IsZero() {
		return kubernetesConfig{}, nil, fmt.Errorf("endpoint and token must be set together (or both omitted to use the in-cluster service account)")
	}
	// Validate and canonicalize an explicit endpoint at parse time (https only, no
	// path), so a malformed endpoint is rejected at manifest normalization rather
	// than only at activation.
	if config.Endpoint != "" {
		normalized, err := k8s.NormalizeEndpoint(config.Endpoint)
		if err != nil {
			return kubernetesConfig{}, nil, err
		}
		config.Endpoint = normalized
	}
	if config.RequestsPerSecond < 0 {
		return kubernetesConfig{}, nil, fmt.Errorf("requests_per_second must not be negative")
	}
	if config.Burst < 0 {
		return kubernetesConfig{}, nil, fmt.Errorf("burst must not be negative")
	}
	if config.TimeoutMS < 0 || config.MaxResponseBytes < 0 {
		return kubernetesConfig{}, nil, fmt.Errorf("timeout_ms and max_response_bytes must not be negative")
	}
	return config, grants, nil
}

// normalizeVerbGrant validates one verb case and its resource rules. get is the
// only verb the driver implements today; naming anything else is refused with a
// clear message, since this is the discriminator a future operation slots into.
func normalizeVerbGrant(grant KubernetesVerbGrant) (KubernetesVerbGrant, error) {
	verb := strings.ToLower(strings.TrimSpace(grant.Verb))
	switch verb {
	case k8s.VerbGet:
	case "":
		return KubernetesVerbGrant{}, fmt.Errorf("verb is required")
	default:
		return KubernetesVerbGrant{}, fmt.Errorf("verb %q is not available; this driver is get-only for now", verb)
	}
	grant.Verb = verb
	if len(grant.Resources) == 0 {
		return KubernetesVerbGrant{}, fmt.Errorf("verb %q grants no resources", verb)
	}
	seen := make(map[string]struct{}, len(grant.Resources))
	rules := make([]KubernetesResourceRule, len(grant.Resources))
	for i, rule := range grant.Resources {
		normalized, err := normalizeResourceRule(rule)
		if err != nil {
			return KubernetesVerbGrant{}, fmt.Errorf("resource %d: %w", i, err)
		}
		key := fmt.Sprintf("%s/%s/%s/%t", normalized.Group, normalized.Version, normalized.Resource, normalized.ClusterScoped)
		if _, dup := seen[key]; dup {
			return KubernetesVerbGrant{}, fmt.Errorf("duplicate resource rule %q (combine its namespaces instead)", normalized.Resource)
		}
		seen[key] = struct{}{}
		rules[i] = normalized
	}
	sortResourceRules(rules)
	grant.Resources = rules
	return grant, nil
}

// normalizeResourceRule validates and canonicalizes one resource rule.
func normalizeResourceRule(rule KubernetesResourceRule) (KubernetesResourceRule, error) {
	rule.Group = strings.TrimSpace(rule.Group)
	rule.Resource = strings.TrimSpace(rule.Resource)
	rule.Version = strings.TrimSpace(rule.Version)
	if rule.Version == "" {
		rule.Version = "v1"
	}
	if err := k8s.ValidateResourceIdentity(rule.Group, rule.Version, rule.Resource); err != nil {
		return KubernetesResourceRule{}, err
	}

	namespaces, err := normalizeNamespaces(rule.Namespaces, rule.ClusterScoped)
	if err != nil {
		return KubernetesResourceRule{}, err
	}
	rule.Namespaces = namespaces

	// A read-only driver reading Secret values would exfiltrate every credential
	// in scope, so a core Secrets rule must be metadata-only. The driver also
	// re-checks this at request time (a hard floor: a Secret body is unreadable
	// even if a grant slipped past this validation).
	if rule.Group == "" && rule.Resource == "secrets" && !rule.MetadataOnly {
		return KubernetesResourceRule{}, fmt.Errorf(`core "secrets" may only be granted with metadata_only: true (reading Secret data is refused)`)
	}

	flow, err := rule.FlowPolicy.Normalized()
	if err != nil {
		return KubernetesResourceRule{}, err
	}
	rule.FlowPolicy = flow
	return rule, nil
}

// normalizeNamespaces validates the namespace allowlist and enforces the scope
// invariant: a cluster-scoped resource takes none, a namespaced one needs at
// least one namespace ("*" — any — is enough).
func normalizeNamespaces(namespaces []string, clusterScoped bool) ([]string, error) {
	if clusterScoped {
		if len(namespaces) > 0 {
			return nil, fmt.Errorf("a cluster-scoped resource must not list namespaces")
		}
		return nil, nil
	}
	seen := make(map[string]struct{}, len(namespaces))
	out := make([]string, 0, len(namespaces))
	for _, namespace := range namespaces {
		namespace = strings.TrimSpace(namespace)
		if namespace != "*" {
			if err := k8s.ValidateNamespaceName(namespace); err != nil {
				return nil, err
			}
		}
		if _, dup := seen[namespace]; dup {
			continue
		}
		seen[namespace] = struct{}{}
		out = append(out, namespace)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("a namespaced resource must grant at least one namespace (or \"*\")")
	}
	sort.Strings(out)
	return out, nil
}

// resolveKubernetesAccess resolves the API-server access and the credential
// label (the token's keyed fingerprint, never its value) stamped on every
// result. An explicit endpoint+token wins; otherwise the in-cluster service
// account is used, and its absence is a fail-closed build error.
func resolveKubernetesAccess(config kubernetesConfig, services Services) (k8s.Access, string, error) {
	if config.Endpoint != "" {
		token, err := config.Token.Resolve(services.Secrets)
		if err != nil {
			return k8s.Access{}, "", err
		}
		clusterAccess, err := k8s.ExplicitAccess(config.Endpoint, config.CACert, token)
		if err != nil {
			return k8s.Access{}, "", err
		}
		name := config.Token.Ref()
		if name == "" {
			name = "inline"
		}
		return clusterAccess, credentialLabel(name, services.AuditKey, token), nil
	}
	clusterAccess, token, err := k8s.InClusterAccess()
	if err != nil {
		return k8s.Access{}, "", fmt.Errorf("core.kubernetes needs an in-cluster service account or an explicit endpoint+token: %w", err)
	}
	return clusterAccess, credentialLabel("k8s-serviceaccount", services.AuditKey, token), nil
}

func credentialLabel(name string, auditKey []byte, token string) string {
	return "credential:" + name + "@" + CredentialFingerprint(auditKey, token)
}

func durationMS(ms int64) time.Duration { return time.Duration(ms) * time.Millisecond }

func sortResourceRules(rules []KubernetesResourceRule) {
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Group != rules[j].Group {
			return rules[i].Group < rules[j].Group
		}
		if rules[i].Resource != rules[j].Resource {
			return rules[i].Resource < rules[j].Resource
		}
		return rules[i].Version < rules[j].Version
	})
}

// kubernetesDescription composes the published capability's tool doc: the
// read-only, rate-limited posture and, per verb, the resources it may read.
func kubernetesDescription(grants []KubernetesVerbGrant) string {
	var b strings.Builder
	b.WriteString("Read Kubernetes objects (read-only; rate-limited; served from the API server cache). Set resource/group/version to match an allowed resource, plus namespace and name.")
	for _, grant := range grants {
		fmt.Fprintf(&b, "\nVerb %q:", grant.Verb)
		for _, rule := range grant.Resources {
			fmt.Fprintf(&b, "\n- resource %q", rule.Resource)
			if rule.Group != "" {
				fmt.Fprintf(&b, " group %q", rule.Group)
			}
			scope := "namespaces " + strings.Join(rule.Namespaces, ",")
			if rule.ClusterScoped {
				scope = "cluster-scoped"
			} else if len(rule.Namespaces) == 1 && rule.Namespaces[0] == "*" {
				scope = "any namespace"
			}
			fmt.Fprintf(&b, " — %s", scope)
			if rule.MetadataOnly {
				b.WriteString(" (metadata only)")
			}
		}
	}
	return b.String()
}
