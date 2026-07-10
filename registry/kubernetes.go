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
// allowlist: a resource type and the namespaces it may be read in, plus its
// data-flow policy. It is the whole allowlist that constrains every read this
// grant can make. There is only one operation — get one object by name — so a
// resource that is granted is a resource the guest may get.
type KubernetesResource struct {
	// Group/Version/Resource identify the resource type; Group "" is the core
	// group, Version defaults to v1.
	Group    string `json:"group,omitempty"`
	Version  string `json:"version,omitempty"`
	Resource string `json:"resource"`
	// Namespaces are the concrete namespaces this resource may be read in.
	// Required for a namespaced resource, and must be empty for a cluster-scoped
	// one. (No wildcard: a namespace must be named explicitly.)
	Namespaces []string `json:"namespaces,omitempty"`
	// ClusterScoped marks a non-namespaced resource (nodes, namespaces,
	// persistentvolumes). Its reads carry no namespace.
	ClusterScoped bool `json:"cluster_scoped,omitempty"`
	// MetadataOnly forces every read of this resource to return only object
	// metadata (names, labels, timestamps) — never the object body. Set it on
	// resources whose payload is sensitive or heavy (a ConfigMap's data) to keep
	// the values out of the guest entirely.
	MetadataOnly    bool  `json:"metadata_only,omitempty"`
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
	for _, resource := range resources {
		permissions = append(permissions, k8s.Permission{
			Group:           resource.Group,
			Version:         resource.Version,
			Resource:        resource.Resource,
			Namespaces:      resource.Namespaces,
			ClusterScoped:   resource.ClusterScoped,
			MetadataOnly:    resource.MetadataOnly,
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

	branch, err := OperationBranch(k8s.VerbGet, getOperationSchema)
	if err != nil {
		return err
	}
	out.Capabilities = append(out.Capabilities, sys.Capability{
		Name:        k8s.Capability,
		Description: kubernetesDescription(resources),
		InputSchema: OneOfSchema([]json.RawMessage{branch}),
	})
	return nil
}

// parseKubernetesConfig validates and canonicalizes a core.kubernetes grant's
// config — the single parse Normalize and Configure share. It rejects unknown
// fields, requires at least one resource, and normalizes each resource's
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

	namespaces, err := normalizeNamespaces(resource.Namespaces, resource.ClusterScoped)
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

// normalizeNamespaces validates the namespace allowlist and enforces the scope
// invariant: a cluster-scoped resource takes none, a namespaced one needs at
// least one concrete namespace (no wildcard).
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
		if err := k8s.ValidateNamespaceName(namespace); err != nil {
			return nil, err
		}
		if _, dup := seen[namespace]; dup {
			continue
		}
		seen[namespace] = struct{}{}
		out = append(out, namespace)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("a namespaced resource must grant at least one namespace")
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
// read-only, get-only, rate-limited posture and the allowed resources.
func kubernetesDescription(resources []KubernetesResource) string {
	var b strings.Builder
	b.WriteString("Read one Kubernetes object by name (read-only; get only, no list; rate-limited; served from the API server cache). Set resource/group/version to match an allowed resource, plus namespace and name. Allowed resources:")
	for _, resource := range resources {
		fmt.Fprintf(&b, "\n- resource %q", resource.Resource)
		if resource.Group != "" {
			fmt.Fprintf(&b, " group %q", resource.Group)
		}
		scope := "namespaces " + strings.Join(resource.Namespaces, ",")
		if resource.ClusterScoped {
			scope = "cluster-scoped"
		}
		fmt.Fprintf(&b, " version %q — %s", resource.Version, scope)
		if resource.MetadataOnly {
			b.WriteString(" (metadata only)")
		}
	}
	return b.String()
}
