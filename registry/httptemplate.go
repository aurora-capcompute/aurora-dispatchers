package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/internet"
	"github.com/aurora-capcompute/capcompute/sys"
)

// HTTPTemplateSyscall is the manifest `syscall` for a templated-request grant and
// the name of the single capability it publishes. Its operations are cases of one
// discriminated ADT, selected by the `operation` field in the call args — and
// each operation is self-contained, so one grant can front several APIs.
const HTTPTemplateSyscall = "core.httpTemplate"

// templatePlaceholderName matches a {{param}} placeholder and captures the name.
var templatePlaceholderName = regexp.MustCompile(`\{\{(\w+)\}\}`)

// validParamTypes are the parameter types a template operation may declare.
var validParamTypes = map[string]struct{}{
	"string": {}, "integer": {}, "number": {}, "boolean": {},
}

// templateConfig is a core.httpTemplate grant's driver configuration: a set of
// named operations plus the shared transport bounds. Each operation targets its
// own origin with its own host-held credential, so a single grant can front
// several APIs; the guest picks one by name and fills only its parameters.
type templateConfig struct {
	// BaseURL is an optional default origin (scheme://host) for operations that
	// give only a path; an operation may override it with its own base_url.
	BaseURL             string              `json:"base_url,omitempty"`
	TimeoutMS           int64               `json:"timeout_ms,omitempty"`
	MaxResponseBytes    int64               `json:"max_response_bytes,omitempty"`
	MaxRequestBytes     int64               `json:"max_request_bytes,omitempty"`
	AllowPrivateNetwork bool                `json:"allow_private_network,omitempty"`
	Operations          []templateOperation `json:"operations"`
}

// templateOperation is one named request the guest may invoke: a fixed origin,
// method, path, optional query and JSON body carrying {{param}} placeholders, the
// parameter contract that decides what the guest may fill, and the credential(s)
// attached host-side for this operation only.
type templateOperation struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Method      string `json:"method"`
	// BaseURL is this operation's origin (scheme://host); it overrides the grant
	// default. Required if the grant sets no default.
	BaseURL string                   `json:"base_url,omitempty"`
	Path    string                   `json:"path"`
	Query   map[string]string        `json:"query,omitempty"`
	Body    json.RawMessage          `json:"body,omitempty"`
	Params  map[string]templateParam `json:"params,omitempty"`
	// InjectHeaders attaches host-held headers (e.g. an Authorization bearer
	// token) to this operation's request, bound to its origin. Per-operation so a
	// credential is never sent to another operation's host.
	InjectHeaders   map[string]HeaderInjection `json:"inject_headers,omitempty"`
	RequireApproval *bool                      `json:"require_approval,omitempty"`
	FlowPolicy
}

// templateParam is one guest-fillable parameter's contract, published into the
// operation's input schema.
type templateParam struct {
	Type        string   `json:"type"`
	Required    bool     `json:"required,omitempty"`
	Description string   `json:"description,omitempty"`
	Enum        []string `json:"enum,omitempty"`
}

type HTTPTemplateRegistration struct{}

func (HTTPTemplateRegistration) Matches(syscall string) bool { return syscall == HTTPTemplateSyscall }

func (HTTPTemplateRegistration) Normalize(_ string, raw json.RawMessage) (json.RawMessage, error) {
	config, err := parseTemplateConfig(raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(config)
}

func (HTTPTemplateRegistration) Configure(_ context.Context, raw json.RawMessage, services Services, out *builtin.Config) error {
	config, err := parseTemplateConfig(raw)
	if err != nil {
		return err
	}
	operations := make(map[string]builtin.TemplateOperation, len(config.Operations))
	branches := make([]json.RawMessage, 0, len(config.Operations))
	for _, operation := range config.Operations {
		// Resolve this operation's host-held credential at activation. A missing
		// referenced secret fails the build here, never silently at request time.
		headers, credentialLabels, err := resolveInjectedHeaders(operation.InjectHeaders, services)
		if err != nil {
			return fmt.Errorf("core.httpTemplate operation %q: %w", operation.Name, err)
		}
		compiled, branch, err := compileOperation(operation, headers, credentialLabels)
		if err != nil {
			return fmt.Errorf("operation %q: %w", operation.Name, err)
		}
		operations[operation.Name] = compiled
		branches = append(branches, branch)
	}

	client := internet.NewConfiguredClient(
		templatePolicy(config),
		time.Duration(config.TimeoutMS)*time.Millisecond,
		config.MaxResponseBytes,
		config.MaxRequestBytes,
	)
	client.AllowPrivateNetwork = config.AllowPrivateNetwork

	out.Handlers = append(out.Handlers, builtin.TemplateHandler{
		Name:       HTTPTemplateSyscall,
		Client:     client,
		Operations: operations,
	})
	out.Capabilities = append(out.Capabilities, sys.Capability{
		Name:        HTTPTemplateSyscall,
		Description: templateDescription(config),
		InputSchema: OneOfSchema(branches),
	})
	return nil
}

// parseTemplateConfig validates and canonicalizes a template grant: at least one
// operation with a unique name, each resolving to a fixed https (or loopback)
// origin, a valid method and absolute path, a JSON body template if present,
// valid parameter types, credential injection bound to the operation's origin,
// and every {{param}} placeholder resolving to a declared parameter. The single
// parse Normalize (which marshals it) and Configure (which builds from it) share.
func parseTemplateConfig(raw json.RawMessage) (templateConfig, error) {
	var config templateConfig
	if len(raw) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config); err != nil {
			return templateConfig{}, err
		}
	}

	var defaultOrigin string
	if strings.TrimSpace(config.BaseURL) != "" {
		origin, err := templateOrigin(config.BaseURL)
		if err != nil {
			return templateConfig{}, fmt.Errorf("base_url: %w", err)
		}
		config.BaseURL, defaultOrigin = origin, origin
	}
	if len(config.Operations) == 0 {
		return templateConfig{}, fmt.Errorf("operations must contain at least one operation")
	}

	seen := make(map[string]struct{}, len(config.Operations))
	for i := range config.Operations {
		operation := &config.Operations[i]
		rawOrigin := strings.TrimSpace(operation.BaseURL)
		if rawOrigin == "" {
			rawOrigin = defaultOrigin
		}
		if rawOrigin == "" {
			return templateConfig{}, fmt.Errorf("operation %d: base_url is required (set it on the operation or as a grant default)", i)
		}
		origin, err := templateOrigin(rawOrigin)
		if err != nil {
			return templateConfig{}, fmt.Errorf("operation %d base_url: %w", i, err)
		}
		operation.BaseURL = origin
		// A credential must be bound to this operation's specific origin.
		if len(operation.InjectHeaders) > 0 {
			if err := validateInjection(origin, operation.InjectHeaders); err != nil {
				return templateConfig{}, fmt.Errorf("operation %d: %w", i, err)
			}
		}
		if err := normalizeOperation(operation); err != nil {
			return templateConfig{}, fmt.Errorf("operation %d: %w", i, err)
		}
		if _, dup := seen[operation.Name]; dup {
			return templateConfig{}, fmt.Errorf("duplicate operation %q", operation.Name)
		}
		seen[operation.Name] = struct{}{}
	}
	sort.Slice(config.Operations, func(i, j int) bool { return config.Operations[i].Name < config.Operations[j].Name })

	config.TimeoutMS = defaultIfZero(config.TimeoutMS, int64(internet.DefaultTimeout/time.Millisecond))
	config.MaxResponseBytes = defaultIfZero(config.MaxResponseBytes, internet.DefaultMaxResponseBytes)
	config.MaxRequestBytes = defaultIfZero(config.MaxRequestBytes, internet.DefaultMaxRequestBytes)
	return config, nil
}

// templateOrigin validates a scheme://host origin (https, or http on loopback
// where there is no wire to sniff) and returns it canonicalized.
func templateOrigin(raw string) (string, error) {
	rule, err := internet.NewRule(internet.AnyMethod, strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if rule.AnyHost {
		return "", fmt.Errorf("origin must be a specific host, not %q", "*")
	}
	if rule.Scheme == "http" && !internet.LoopbackHost(rule.Host) {
		return "", fmt.Errorf("origin must be https (host %q is plain http)", rule.Host)
	}
	return rule.Scheme + "://" + rule.Host, nil
}

// normalizeOperation validates and canonicalizes one operation's method, path,
// body, parameters, flow policy, and placeholder references in place. The origin
// and credential injection are validated by the caller.
func normalizeOperation(operation *templateOperation) error {
	operation.Name = strings.TrimSpace(operation.Name)
	if operation.Name == "" {
		return fmt.Errorf("name is required")
	}
	operation.Method = strings.ToUpper(strings.TrimSpace(operation.Method))
	if operation.Method == "" || operation.Method == internet.AnyMethod {
		return fmt.Errorf("method must be a specific HTTP method")
	}
	operation.Path = strings.TrimSpace(operation.Path)
	if !strings.HasPrefix(operation.Path, "/") {
		return fmt.Errorf("path must start with %q", "/")
	}
	if len(operation.Body) > 0 && !json.Valid(operation.Body) {
		return fmt.Errorf("body must be valid JSON")
	}
	for name, param := range operation.Params {
		if _, ok := validParamTypes[param.Type]; !ok {
			return fmt.Errorf("parameter %q has invalid type %q (want string|integer|number|boolean)", name, param.Type)
		}
	}
	flow, err := operation.FlowPolicy.Normalized()
	if err != nil {
		return err
	}
	operation.FlowPolicy = flow
	for _, ref := range placeholderRefs(operation) {
		if _, ok := operation.Params[ref]; !ok {
			return fmt.Errorf("placeholder {{%s}} has no matching parameter", ref)
		}
	}
	return nil
}

// placeholderRefs returns every parameter name referenced by a {{...}} in the
// operation's path, query values, or body.
func placeholderRefs(operation *templateOperation) []string {
	var refs []string
	collect := func(text string) {
		for _, match := range templatePlaceholderName.FindAllStringSubmatch(text, -1) {
			refs = append(refs, match[1])
		}
	}
	collect(operation.Path)
	for _, value := range operation.Query {
		collect(value)
	}
	collect(string(operation.Body))
	return refs
}

// compileOperation builds the handler-side operation (with its resolved headers
// and audit labels) and its published input schema branch.
func compileOperation(operation templateOperation, headers map[string]string, credentialLabels []string) (builtin.TemplateOperation, json.RawMessage, error) {
	var body any
	if len(operation.Body) > 0 {
		if err := json.Unmarshal(operation.Body, &body); err != nil {
			return builtin.TemplateOperation{}, nil, err
		}
	}
	params := make(map[string]builtin.TemplateParam, len(operation.Params))
	for name, param := range operation.Params {
		params[name] = builtin.TemplateParam{Type: param.Type, Required: param.Required}
	}
	compiled := builtin.TemplateOperation{
		Name:             operation.Name,
		Method:           operation.Method,
		BaseURL:          operation.BaseURL,
		Path:             operation.Path,
		Query:            operation.Query,
		Body:             body,
		Params:           params,
		Headers:          headers,
		CredentialLabels: credentialLabels,
		Labels:           operation.FlowPolicy.Labels,
		Taints:           operation.FlowPolicy.Taints,
		RequireApproval:  operation.RequireApproval != nil && *operation.RequireApproval,
	}
	branch, err := OperationBranch(operation.Name, operationParamSchema(operation))
	if err != nil {
		return builtin.TemplateOperation{}, nil, err
	}
	return compiled, branch, nil
}

// operationParamSchema builds the closed object schema for an operation's
// parameters (the discriminator is added by OperationBranch).
func operationParamSchema(operation templateOperation) json.RawMessage {
	properties := make(map[string]json.RawMessage, len(operation.Params))
	var required []string
	for name, param := range operation.Params {
		spec := map[string]any{"type": param.Type}
		if param.Description != "" {
			spec["description"] = param.Description
		}
		if len(param.Enum) > 0 {
			spec["enum"] = param.Enum
		}
		properties[name], _ = json.Marshal(spec)
		if param.Required {
			required = append(required, name)
		}
	}
	sort.Strings(required)
	schema := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties":           properties,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	raw, _ := json.Marshal(schema)
	return raw
}

// templatePolicy is the egress allowlist: each operation's method against its own
// origin (unioned, deduplicated), so a constructed request can reach only what
// the grant's operations define.
func templatePolicy(config templateConfig) internet.Policy {
	seen := make(map[string]struct{}, len(config.Operations))
	var rules []internet.Rule
	for _, operation := range config.Operations {
		key := operation.Method + " " + operation.BaseURL
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		// Origin and method already validated in parseTemplateConfig.
		rule, _ := internet.NewRule(operation.Method, operation.BaseURL)
		rules = append(rules, rule)
	}
	return internet.NewPolicy(rules...)
}

func templateDescription(config templateConfig) string {
	var b strings.Builder
	b.WriteString("Call a named operation; fill only its declared parameters. Operations:")
	for _, operation := range config.Operations {
		fmt.Fprintf(&b, "\n- %s (%s %s%s)", operation.Name, operation.Method, operation.BaseURL, operation.Path)
		if operation.Description != "" {
			b.WriteString(": ")
			b.WriteString(operation.Description)
		}
	}
	return b.String()
}

func defaultIfZero(value, fallback int64) int64 {
	if value <= 0 {
		return fallback
	}
	return value
}
