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

// KubernetesResource is one entry of a core.kubernetes grant's `capabilities`
// allowlist: a resource type, the read verbs enabled on it (get and/or list —
// there are no write verbs), the namespaces it reaches, and its data-flow policy.
// It is the whole allowlist that constrains every read this grant can make.
type KubernetesResource struct {
	// Verbs are the read verbs enabled: any of "get", "list". Empty grants both.
	Verbs []string `json:"verbs,omitempty"`
	// Group/Version/Resource identify the resource type; Group "" is the core
	// group, Version defaults to v1.
	Group    string `json:"group,omitempty"`
	Version  string `json:"version,omitempty"`
	Resource string `json:"resource"`
	// Namespaces are the namespaces this resource may be read in; "*" means any
	// (a list may then omit the namespace to read across all of them, still
	// bounded by the page limit). Required for a namespaced resource, and must be
	// empty for a cluster-scoped one.
	Namespaces []string `json:"namespaces,omitempty"`
	// ClusterScoped marks a non-namespaced resource (nodes, namespaces,
	// persistentvolumes). Its reads carry no namespace.
	ClusterScoped bool `json:"cluster_scoped,omitempty"`
	// MetadataOnly forces every read of this resource to return only object
	// metadata (names, labels, timestamps) — never the object body. Set it on
	// resources whose payload is sensitive or heavy (a ConfigMap's data) to keep
	// the values out of the guest entirely.
	MetadataOnly bool `json:"metadata_only,omitempty"`
	// StrongRead reads through to etcd (a quorum read) instead of the API
	// server's watch cache. Off by default: cache reads are far lighter on the
	// cluster, at the cost of possibly-slightly-stale data.
	StrongRead      bool  `json:"strong_read,omitempty"`
	RequireApproval *bool `json:"require_approval,omitempty"`
	FlowPolicy
}

// kubernetesConfig is a core.kubernetes grant's driver configuration: the
// resource allowlist, an optional explicit API-server override (else the pod's
// in-cluster service account is used), and the request bounds and pacing that
// keep the driver gentle on the API server.
type kubernetesConfig struct {
	Capabilities []KubernetesResource `json:"capabilities,omitempty"`
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

// kubernetesOperations are the two read verbs, each with the guest-input schema
// its args carry (minus the `operation` discriminator OperationBranch injects).
var kubernetesOperations = map[string]struct {
	schema      json.RawMessage
	description string
}{
	k8s.VerbGet: {
		schema:      json.RawMessage(`{"type":"object","properties":{"group":{"type":"string"},"version":{"type":"string"},"resource":{"type":"string","minLength":1},"namespace":{"type":"string"},"name":{"type":"string","minLength":1},"metadata_only":{"type":"boolean"}},"required":["resource","name"],"additionalProperties":false}`),
		description: "get: read one object by name (namespace required for namespaced resources)",
	},
	k8s.VerbList: {
		schema:      json.RawMessage(`{"type":"object","properties":{"group":{"type":"string"},"version":{"type":"string"},"resource":{"type":"string","minLength":1},"namespace":{"type":"string"},"label_selector":{"type":"string"},"field_selector":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":500},"continue":{"type":"string"},"metadata_only":{"type":"boolean"}},"required":["resource"],"additionalProperties":false}`),
		description: "list: read a bounded page of a collection (optional label_selector/field_selector to narrow, limit to size, continue to page)",
	},
}

// KubernetesRegistration provides a read-only, rate-limited window onto a
// Kubernetes API server. It publishes core.kubernetes with get and list
// operations over an author-declared resource allowlist; there is no write path.
type KubernetesRegistration struct{}

func (KubernetesRegistration) Matches(syscall string) bool { return syscall == k8s.Capability }

func (KubernetesRegistration) Normalize(_ string, raw json.RawMessage) (json.RawMessage, error) {
	config, resources, err := parseKubernetesConfig(raw)
	if err != nil {
		return nil, err
	}
	config.Capabilities = resources
	return json.Marshal(config)
}

func (KubernetesRegistration) Configure(_ context.Context, raw json.RawMessage, services Services, out *builtin.Config) error {
	config, resources, err := parseKubernetesConfig(raw)
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

	permissions := make([]k8s.Permission, 0, len(resources))
	verbsGranted := map[string]bool{}
	for _, resource := range resources {
		verbs := map[string]bool{}
		for _, verb := range resource.Verbs {
			verbs[verb] = true
			verbsGranted[verb] = true
		}
		permissions = append(permissions, k8s.Permission{
			Group:           resource.Group,
			Version:         resource.Version,
			Resource:        resource.Resource,
			Verbs:           verbs,
			Namespaces:      resource.Namespaces,
			ClusterScoped:   resource.ClusterScoped,
			MetadataOnly:    resource.MetadataOnly,
			StrongRead:      resource.StrongRead,
			RequireApproval: resource.RequireApproval != nil && *resource.RequireApproval,
			Labels:          resource.Labels,
			Taints:          resource.Taints,
		})
	}

	out.Handlers = append(out.Handlers, k8s.Handler{
		Name:            k8s.Capability,
		CredentialLabel: credentialLabel,
		Client:          client,
		Resources:       permissions,
	})

	branches := make([]json.RawMessage, 0, 2)
	for _, verb := range []string{k8s.VerbGet, k8s.VerbList} {
		if !verbsGranted[verb] {
			continue
		}
		branch, err := OperationBranch(verb, kubernetesOperations[verb].schema)
		if err != nil {
			return err
		}
		branches = append(branches, branch)
	}
	out.Capabilities = append(out.Capabilities, sys.Capability{
		Name:        k8s.Capability,
		Description: kubernetesDescription(resources, verbsGranted),
		InputSchema: OneOfSchema(branches),
	})
	return nil
}

// parseKubernetesConfig validates and canonicalizes a core.kubernetes grant's
// config — the single parse Normalize and Configure share. It rejects unknown
// fields, requires at least one resource, and normalizes each resource's verbs,
// version, namespaces, and flow policy.
func parseKubernetesConfig(raw json.RawMessage) (kubernetesConfig, []KubernetesResource, error) {
	var config kubernetesConfig
	if len(raw) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config); err != nil {
			return kubernetesConfig{}, nil, err
		}
	}
	if len(config.Capabilities) == 0 {
		return kubernetesConfig{}, nil, fmt.Errorf("capabilities must grant at least one resource")
	}
	seen := make(map[string]struct{}, len(config.Capabilities))
	resources := make([]KubernetesResource, len(config.Capabilities))
	for i, resource := range config.Capabilities {
		normalized, err := normalizeResource(resource)
		if err != nil {
			return kubernetesConfig{}, nil, fmt.Errorf("resource %d: %w", i, err)
		}
		key := normalized.Group + "/" + normalized.Version + "/" + normalized.Resource
		if _, dup := seen[key]; dup {
			return kubernetesConfig{}, nil, fmt.Errorf("duplicate resource %q", key)
		}
		seen[key] = struct{}{}
		resources[i] = normalized
	}
	sortKubernetesResources(resources)

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
	return config, resources, nil
}

// normalizeResource validates and canonicalizes one allowlist entry.
func normalizeResource(resource KubernetesResource) (KubernetesResource, error) {
	resource.Group = strings.TrimSpace(resource.Group)
	resource.Version = strings.TrimSpace(resource.Version)
	if resource.Version == "" {
		resource.Version = "v1"
	}
	resource.Resource = strings.TrimSpace(resource.Resource)
	if err := k8s.ValidateResourceIdentity(resource.Group, resource.Version, resource.Resource); err != nil {
		return KubernetesResource{}, err
	}

	verbs, err := normalizeVerbs(resource.Verbs)
	if err != nil {
		return KubernetesResource{}, err
	}
	resource.Verbs = verbs

	namespaces, err := normalizeNamespaces(resource.Namespaces, resource.ClusterScoped, verbs)
	if err != nil {
		return KubernetesResource{}, err
	}
	resource.Namespaces = namespaces

	// A read-only driver reading Secret values would exfiltrate every credential
	// in scope, so core Secrets may be granted for their metadata only (names and
	// labels, never data). Remove this rail deliberately if a use case needs it.
	if resource.Group == "" && resource.Resource == "secrets" && !resource.MetadataOnly {
		return KubernetesResource{}, fmt.Errorf(`core "secrets" may only be granted with metadata_only: true (reading Secret data is refused)`)
	}

	flow, err := resource.FlowPolicy.Normalized()
	if err != nil {
		return KubernetesResource{}, err
	}
	resource.FlowPolicy = flow
	return resource, nil
}

// normalizeVerbs canonicalizes the read verbs, defaulting an empty list to both
// get and list, and rejecting anything that is not a read.
func normalizeVerbs(verbs []string) ([]string, error) {
	if len(verbs) == 0 {
		return []string{k8s.VerbGet, k8s.VerbList}, nil
	}
	seen := make(map[string]struct{}, len(verbs))
	out := make([]string, 0, len(verbs))
	for _, verb := range verbs {
		verb = strings.ToLower(strings.TrimSpace(verb))
		switch verb {
		case k8s.VerbGet, k8s.VerbList:
		default:
			return nil, fmt.Errorf("verb %q is not a read verb (only get and list are supported)", verb)
		}
		if _, dup := seen[verb]; dup {
			continue
		}
		seen[verb] = struct{}{}
		out = append(out, verb)
	}
	sort.Strings(out)
	return out, nil
}

// normalizeNamespaces validates the namespace allowlist and enforces the
// scope invariant: a cluster-scoped resource takes none, a namespaced one that
// enables get needs at least one (a bare "*" is enough).
func normalizeNamespaces(namespaces []string, clusterScoped bool, verbs []string) ([]string, error) {
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

func sortKubernetesResources(resources []KubernetesResource) {
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].Group != resources[j].Group {
			return resources[i].Group < resources[j].Group
		}
		if resources[i].Resource != resources[j].Resource {
			return resources[i].Resource < resources[j].Resource
		}
		return resources[i].Version < resources[j].Version
	})
}

// kubernetesDescription composes the published capability's tool doc: the
// read-only, rate-limited posture and the allowed resources.
func kubernetesDescription(resources []KubernetesResource, verbsGranted map[string]bool) string {
	var b strings.Builder
	b.WriteString("Read Kubernetes objects (read-only, rate-limited, served from the API server cache). Choose an operation:")
	for _, verb := range []string{k8s.VerbGet, k8s.VerbList} {
		if verbsGranted[verb] {
			fmt.Fprintf(&b, "\n- %s", kubernetesOperations[verb].description)
		}
	}
	b.WriteString("\nAllowed resources (set resource/group/version to match one):")
	for _, resource := range resources {
		fmt.Fprintf(&b, "\n- resource %q", resource.Resource)
		if resource.Group != "" {
			fmt.Fprintf(&b, " group %q", resource.Group)
		}
		scope := "namespaces " + strings.Join(resource.Namespaces, ",")
		if resource.ClusterScoped {
			scope = "cluster-scoped"
		}
		fmt.Fprintf(&b, " version %q — %s, %s", resource.Version, strings.Join(resource.Verbs, "/"), scope)
		if resource.MetadataOnly {
			b.WriteString(" (metadata only)")
		}
	}
	return b.String()
}
