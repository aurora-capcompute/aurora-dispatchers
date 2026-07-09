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
// discriminated ADT, selected by the `operation` field in the call args.
const HTTPTemplateSyscall = "core.httpTemplate"

// templatePlaceholderName matches a {{param}} placeholder and captures the name.
var templatePlaceholderName = regexp.MustCompile(`\{\{(\w+)\}\}`)

// validParamTypes are the parameter types a template operation may declare.
var validParamTypes = map[string]struct{}{
	"string": {}, "integer": {}, "number": {}, "boolean": {},
}

// templateConfig is a core.httpTemplate grant's driver configuration: the fixed
// origin every operation targets, the credential(s) attached host-side, the
// response/request bounds, and the operation set. The guest may invoke an
// operation and fill its declared parameters — nothing else on the origin.
type templateConfig struct {
	BaseURL             string                     `json:"base_url"`
	TimeoutMS           int64                      `json:"timeout_ms,omitempty"`
	MaxResponseBytes    int64                      `json:"max_response_bytes,omitempty"`
	MaxRequestBytes     int64                      `json:"max_request_bytes,omitempty"`
	AllowPrivateNetwork bool                       `json:"allow_private_network,omitempty"`
	InjectHeaders       map[string]HeaderInjection `json:"inject_headers,omitempty"`
	Operations          []templateOperation        `json:"operations"`
}

// templateOperation is one named request the guest may invoke: a fixed method,
// path, optional query and JSON body carrying {{param}} placeholders, and the
// parameter contract that decides what the guest may fill.
type templateOperation struct {
	Name            string                   `json:"name"`
	Description     string                   `json:"description,omitempty"`
	Method          string                   `json:"method"`
	Path            string                   `json:"path"`
	Query           map[string]string        `json:"query,omitempty"`
	Body            json.RawMessage          `json:"body,omitempty"`
	Params          map[string]templateParam `json:"params,omitempty"`
	RequireApproval *bool                    `json:"require_approval,omitempty"`
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
	// Resolve the host-held credential(s) at activation. A missing referenced
	// secret fails the build here, never silently at request time.
	headers, credentialLabels, err := resolveInjectedHeaders(config.InjectHeaders, services)
	if err != nil {
		return fmt.Errorf("core.httpTemplate: %w", err)
	}

	client := internet.NewConfiguredClient(
		templatePolicy(config),
		time.Duration(config.TimeoutMS)*time.Millisecond,
		config.MaxResponseBytes,
		config.MaxRequestBytes,
	)
	client.AllowPrivateNetwork = config.AllowPrivateNetwork

	operations := make(map[string]builtin.TemplateOperation, len(config.Operations))
	branches := make([]json.RawMessage, 0, len(config.Operations))
	for _, operation := range config.Operations {
		compiled, branch, err := compileOperation(operation)
		if err != nil {
			return fmt.Errorf("operation %q: %w", operation.Name, err)
		}
		operations[operation.Name] = compiled
		branches = append(branches, branch)
	}

	out.Handlers = append(out.Handlers, builtin.TemplateHandler{
		Name:             HTTPTemplateSyscall,
		BaseURL:          config.BaseURL,
		Headers:          headers,
		CredentialLabels: credentialLabels,
		Client:           client,
		Operations:       operations,
	})
	out.Capabilities = append(out.Capabilities, sys.Capability{
		Name:        HTTPTemplateSyscall,
		Description: templateDescription(config),
		InputSchema: OneOfSchema(branches),
	})
	return nil
}

// parseTemplateConfig validates and canonicalizes a template grant: a fixed
// https (or loopback) origin, at least one operation with a unique name, a valid
// method and absolute path, a JSON body template if present, valid parameter
// types, and every {{param}} placeholder resolving to a declared parameter. The
// single parse Normalize (which marshals it) and Configure (which builds from it)
// share.
func parseTemplateConfig(raw json.RawMessage) (templateConfig, error) {
	var config templateConfig
	if len(raw) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config); err != nil {
			return templateConfig{}, err
		}
	}

	// The origin is a fixed scheme+host, https or loopback — a credential-bearing
	// grant must not send in the clear, and the path is per-operation.
	origin, err := internet.NewRule(internet.AnyMethod, strings.TrimSpace(config.BaseURL))
	if err != nil {
		return templateConfig{}, fmt.Errorf("base_url: %w", err)
	}
	if origin.Scheme == "http" && !isLoopbackHost(origin.Host) {
		return templateConfig{}, fmt.Errorf("base_url must be https (host %q is plain http)", origin.Host)
	}
	config.BaseURL = origin.Scheme + "://" + origin.Host

	if len(config.InjectHeaders) > 0 {
		if err := validateInjection(config.BaseURL, config.InjectHeaders); err != nil {
			return templateConfig{}, err
		}
	}
	if len(config.Operations) == 0 {
		return templateConfig{}, fmt.Errorf("operations must contain at least one operation")
	}

	seen := make(map[string]struct{}, len(config.Operations))
	for i := range config.Operations {
		operation := &config.Operations[i]
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

// normalizeOperation validates and canonicalizes one operation in place.
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
	// Every placeholder must resolve to a declared parameter, so a manifest typo
	// surfaces now rather than sending a literal "{{...}}" to the origin.
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

// compileOperation builds the handler-side operation and its published input
// schema branch.
func compileOperation(operation templateOperation) (builtin.TemplateOperation, json.RawMessage, error) {
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
		Name:            operation.Name,
		Method:          operation.Method,
		Path:            operation.Path,
		Query:           operation.Query,
		Body:            body,
		Params:          params,
		Labels:          operation.FlowPolicy.Labels,
		Taints:          operation.FlowPolicy.Taints,
		RequireApproval: operation.RequireApproval != nil && *operation.RequireApproval,
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

// templatePolicy is the egress allowlist: each operation's method against the
// fixed origin, so the constructed request can reach only what the grant defines.
func templatePolicy(config templateConfig) internet.Policy {
	seen := make(map[string]struct{}, len(config.Operations))
	var rules []internet.Rule
	for _, operation := range config.Operations {
		if _, ok := seen[operation.Method]; ok {
			continue
		}
		seen[operation.Method] = struct{}{}
		// base_url already validated in parseTemplateConfig, so NewRule cannot fail.
		rule, _ := internet.NewRule(operation.Method, config.BaseURL)
		rules = append(rules, rule)
	}
	return internet.NewPolicy(rules...)
}

func templateDescription(config templateConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Call a named operation against %s; fill only the declared parameters. Operations:", config.BaseURL)
	for _, operation := range config.Operations {
		fmt.Fprintf(&b, "\n- %s (%s %s)", operation.Name, operation.Method, operation.Path)
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
