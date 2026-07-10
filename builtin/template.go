package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/aurora-capcompute/aurora-dispatchers/internet"
	"github.com/aurora-capcompute/capcompute/sys"
)

// TemplateHandler serves a manifest-defined family of HTTP operations whose
// method, host, path, headers, and body shape are fixed by the manifest — the
// guest supplies only the declared parameters. It is the operation-level
// least-privilege counterpart to InternetHandler: where core.internet hands the
// guest the whole request (any method/url the allowlist permits), a template
// grant lets the guest fill named holes in one exact request and reach nothing
// else. Credentials are host-attached (never guest-supplied), and guest values
// enter the request only through encoding-safe substitution — percent-encoded in
// the path/query, structurally in the JSON body — so a value can never break out
// of its slot to alter the method, host, path, or JSON shape.
type TemplateHandler struct {
	Name   string
	Client InternetClient
	// Operations is the published operation set, keyed by name. Each operation
	// carries its own origin and its own host-held credential, so one grant can
	// front several APIs — the ADT over `operation` is the menu.
	Operations map[string]TemplateOperation
}

// TemplateOperation is one fixed request the guest may invoke by name, with the
// declared parameters substituted into its path, query, and body. Each operation
// is self-contained: its own origin, its own host-attached credential, and its
// own flow policy — so operations in one grant may target different hosts.
type TemplateOperation struct {
	Name   string
	Method string
	// BaseURL is this operation's fixed scheme://host.
	BaseURL string
	// Path is the fixed path (starting with "/"), optionally carrying {{param}}
	// placeholders substituted percent-encoded.
	Path string
	// Query maps a query-parameter name to a literal or a {{param}} template; each
	// value is percent-encoded when the URL is assembled.
	Query map[string]string
	// Body is the parsed JSON template (nil for no body). A string leaf equal to
	// "{{param}}" is replaced by that parameter's typed JSON value; an embedded
	// {{param}} is replaced by its string form. Substitution is structural, so a
	// value cannot inject JSON syntax.
	Body   any
	Params map[string]TemplateParam
	// Headers are the host-held request headers (e.g. an injected Authorization)
	// attached to this operation only, bound to its origin. The guest can neither
	// supply nor read them.
	Headers map[string]string
	// CredentialLabels name this operation's injected credential(s) for the journal
	// — the keyed fingerprint, never the value — stamped on its result.
	CredentialLabels []string
	// Labels/Taints/RequireApproval are this operation's flow and approval policy,
	// enforced exactly as for core.internet.
	Labels          []string
	Taints          []string
	RequireApproval bool
}

// TemplateParam is one guest-fillable parameter's contract.
type TemplateParam struct {
	Type     string // "string" | "integer" | "number" | "boolean"
	Required bool
}

var templatePlaceholder = regexp.MustCompile(`\{\{(\w+)\}\}`)

func (h TemplateHandler) Handles(name string) bool { return name == h.Name }

func (h TemplateHandler) DispatchCall(ctx context.Context, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if h.Client == nil {
		return sys.FailCode(sys.ErrnoNotFound, "template client is not configured"), nil
	}
	var envelope struct {
		Operation string `json:"operation"`
	}
	if err := json.Unmarshal(call.Args, &envelope); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s call: %v", h.Name, err)), nil
	}
	operation, ok := h.Operations[envelope.Operation]
	if !ok {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("unknown operation %q", envelope.Operation)), nil
	}
	params, err := extractParams(operation, call.Args)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
	}
	// Sink guard: refuse before the request leaves if the run has observed a label
	// this operation forbids.
	if blocked := sys.BlockedBy(sys.Taint(ctx), operation.Taints); len(blocked) > 0 {
		return sys.FailCode(sys.ErrnoDenied, fmt.Sprintf(
			"flow policy: this run has observed %v, which may not flow into %s", blocked, operation.Name)), nil
	}
	if operation.RequireApproval && auth.Decision != sys.Approved {
		return sys.Yield(fmt.Sprintf("Approve %s", operation.Name)), nil
	}

	request, err := h.render(operation, params)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
	}
	reqCtx := ctx
	if len(operation.Headers) > 0 {
		// The operation's host-held headers are bound to its fixed BaseURL origin;
		// bind them so a redirect off that origin drops them rather than carrying
		// this operation's credential to another operation's (or an attacker's) host.
		if u, perr := url.Parse(operation.BaseURL); perr == nil && u.Host != "" {
			reqCtx = internet.WithInjectedCredential(ctx, internet.OriginOf(u), credentialHeaderNames(operation.Headers))
		}
	}
	response, err := h.Client.Do(reqCtx, request)
	if err != nil {
		if ctx.Err() != nil {
			return sys.SyscallResult{}, ctx.Err()
		}
		// A failed attempt still carries the operation's source labels (plus its
		// credential provenance): the error is derived from a request to a labeled
		// origin, so taint the run as if the read happened rather than let a failed
		// call's message reach a forbidding sink untainted.
		return sys.FailCode(sys.ErrnoTransient, err.Error()).WithLabels(
			append(append([]string(nil), operation.Labels...), operation.CredentialLabels...)...), nil
	}
	result, err := marshalResult(response)
	if err != nil {
		return result, err
	}
	return result.WithLabels(append(append([]string(nil), operation.Labels...), operation.CredentialLabels...)...), nil
}

// credentialHeaderNames returns the host-held header names bound to an
// operation's origin, for redirect-time stripping.
func credentialHeaderNames(headers map[string]string) []string {
	if len(headers) == 0 {
		return nil
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	return names
}

// render assembles the concrete request from the operation's fixed template and
// the validated parameters. Every guest value is placed through an encoding that
// keeps it inside its slot: PathEscape in the path, query-encoding in the query,
// and structural JSON substitution in the body.
func (h TemplateHandler) render(operation TemplateOperation, params map[string]any) (internet.Request, error) {
	target := operation.BaseURL + expandString(operation.Path, params, url.PathEscape)
	if len(operation.Query) > 0 {
		values := url.Values{}
		for key, tmpl := range operation.Query {
			values.Set(key, expandString(tmpl, params, nil))
		}
		target += "?" + values.Encode()
	}

	var body string
	if operation.Body != nil {
		rendered := substituteJSON(operation.Body, params)
		raw, err := json.Marshal(rendered)
		if err != nil {
			return internet.Request{}, fmt.Errorf("render body: %w", err)
		}
		body = string(raw)
	}

	headers := make(map[string]string, len(operation.Headers)+1)
	for name, value := range operation.Headers {
		headers[name] = value
	}
	// The template body is JSON, so declare it — without Content-Type a JSON API
	// (FastAPI and the like) ignores the body and rejects the request as if the
	// fields were missing (a 422). A host-set header of the same name wins.
	if body != "" {
		if _, ok := headers["Content-Type"]; !ok {
			headers["Content-Type"] = "application/json"
		}
	}
	return internet.Request{Method: operation.Method, URL: target, Headers: headers, Body: body}, nil
}

// expandString replaces every {{param}} in text with its parameter's string
// form, optionally passed through an escaper (PathEscape for a path segment; nil
// for a query value, which url.Values encodes on its own). A placeholder for an
// absent parameter is left intact.
func expandString(text string, params map[string]any, escape func(string) string) string {
	return templatePlaceholder.ReplaceAllStringFunc(text, func(match string) string {
		name := templatePlaceholder.FindStringSubmatch(match)[1]
		value, ok := params[name]
		if !ok {
			return match
		}
		s := valueString(value)
		if escape != nil {
			s = escape(s)
		}
		return s
	})
}

// substituteJSON walks a parsed JSON template and replaces placeholders. A string
// leaf that is exactly "{{param}}" becomes that parameter's typed value (a JSON
// string/number/bool); an embedded {{param}} is expanded within the string. All
// other nodes are unchanged. Because substitution happens on the parsed structure
// and the result is re-marshaled, a guest value can never inject JSON syntax.
func substituteJSON(node any, params map[string]any) any {
	switch value := node.(type) {
	case string:
		if name, ok := wholePlaceholder(value); ok {
			if pv, present := params[name]; present {
				return pv
			}
			return value
		}
		return expandString(value, params, nil)
	case map[string]any:
		out := make(map[string]any, len(value))
		for key, child := range value {
			out[key] = substituteJSON(child, params)
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, child := range value {
			out[i] = substituteJSON(child, params)
		}
		return out
	default:
		return node
	}
}

// wholePlaceholder reports whether s is exactly one "{{param}}" and returns the
// parameter name.
func wholePlaceholder(s string) (string, bool) {
	match := templatePlaceholder.FindStringSubmatch(s)
	if match != nil && match[0] == s {
		return match[1], true
	}
	return "", false
}

func valueString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	default:
		return fmt.Sprint(v)
	}
}

// extractParams validates the guest's call arguments against the operation's
// declared parameters and coerces them to typed Go values for substitution. The
// kernel already validates the args against the published schema; this is the
// driver's own defensive check.
func extractParams(operation TemplateOperation, raw json.RawMessage) (map[string]any, error) {
	var all map[string]any
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, fmt.Errorf("decode parameters: %w", err)
	}
	params := make(map[string]any, len(operation.Params))
	for name, spec := range operation.Params {
		value, present := all[name]
		if !present {
			if spec.Required {
				return nil, fmt.Errorf("missing required parameter %q", name)
			}
			continue
		}
		coerced, err := coerceParam(name, spec.Type, value)
		if err != nil {
			return nil, err
		}
		params[name] = coerced
	}
	return params, nil
}

func coerceParam(name, kind string, value any) (any, error) {
	switch kind {
	case "string":
		if s, ok := value.(string); ok {
			return s, nil
		}
	case "boolean":
		if b, ok := value.(bool); ok {
			return b, nil
		}
	case "number":
		if f, ok := value.(float64); ok {
			return f, nil
		}
	case "integer":
		if f, ok := value.(float64); ok && f == math.Trunc(f) {
			return int64(f), nil
		}
	default:
		return value, nil
	}
	return nil, fmt.Errorf("parameter %q must be %s", name, strings.TrimSpace(kind))
}
