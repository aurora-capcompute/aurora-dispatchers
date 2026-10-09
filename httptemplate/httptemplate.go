// Package httptemplate serves core.httpTemplate: a manifest-defined family of
// fixed HTTP operations whose method, host, path, headers, and body shape the
// guest cannot change — it only fills named holes. It is the operation-level
// least-privilege counterpart to core.internet, and it makes its requests
// through the same client.
package httptemplate

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"

	"github.com/aurora-capcompute/aurora-dispatchers/internet"
	"github.com/aurora-capcompute/capcompute/sys"
)

// Handler serves one manifest-defined HTTP operation whose method, host, path,
// headers, and body shape are fixed by the manifest — the guest supplies only
// the declared parameters. A grant builds one handler per operation. Where
// core.internet hands the guest the whole request (any method and URL the
// allowlist permits), a template lets the guest fill named holes in one exact
// request and reach nothing else. Credentials are host-attached (never
// guest-supplied), and guest values enter the request only through
// encoding-safe substitution — percent-encoded in the path and query,
// structurally in the JSON body — so a value can never break out of its slot to
// alter the method, host, path, or JSON shape.
type Handler struct {
	Client internet.Doer
	// Operation is the one request this handler sends. Each operation carries
	// its own origin and its own host-held credential, so one grant can front
	// several APIs.
	Operation Operation
}

// Operation is one fixed request the guest may invoke by name, with the
// declared parameters substituted into its path, query, and body. Each operation
// is self-contained: its own origin, its own host-attached credential, and its
// own flow policy — so operations in one grant may target different hosts.
type Operation struct {
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
	Params map[string]Param
	// Headers are the host-held request headers (e.g. an injected Authorization)
	// attached to this operation only, bound to its origin. The guest can neither
	// supply nor read them.
	Headers map[string]string
	// CredentialLabels name this operation's injected credential(s) for the journal
	// — the keyed fingerprint, never the value — stamped on its result.
	CredentialLabels []string
	// Labels/Taints/RequireApproval are this operation's flow and approval
	// policy. They are read here only to be published on the operation's entry;
	// enforcement is the runtime's, above and below the replay tape.
	Labels          []string
	Taints          []string
	RequireApproval bool
}

// Param is one guest-fillable parameter's declared JSON type: "string",
// "integer", "number" or "boolean".
type Param struct {
	Type string
}

var placeholder = regexp.MustCompile(`\{\{(\w+)\}\}`)

// DispatchCall renders the operation's request and sends it. Flow policy and
// approval are the operation's entry's, enforced by the runtime above and below
// the replay tape.
func (h Handler) DispatchCall(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error) {
	params, err := decodeParams(h.Operation, call.Args)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
	}
	request, err := render(h.Operation, params)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
	}
	if len(h.Operation.Headers) > 0 {
		// The operation's host-held headers are bound to its fixed origin, so a
		// redirect off that origin drops them rather than carrying this
		// operation's credential to another host. The registration validated
		// the origin.
		origin, _ := url.Parse(h.Operation.BaseURL)
		ctx = internet.WithInjectedCredential(ctx, internet.OriginOf(origin), slices.Collect(maps.Keys(h.Operation.Headers)))
	}
	response, err := h.Client.Do(ctx, request)
	if err != nil {
		if ctx.Err() != nil {
			return sys.SyscallResult{}, ctx.Err()
		}
		return sys.FailCode(sys.ErrnoTransient, err.Error()), nil
	}
	raw, err := json.Marshal(response)
	if err != nil {
		return sys.SyscallResult{}, err
	}
	return sys.Result(raw), nil
}

// render assembles the concrete request from the operation's fixed template and
// the validated parameters. Every guest value is placed through an encoding that
// keeps it inside its slot: PathEscape in the path, query-encoding in the query,
// and structural JSON substitution in the body.
func render(operation Operation, params map[string]any) (internet.Request, error) {
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
	maps.Copy(headers, operation.Headers)
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
	return placeholder.ReplaceAllStringFunc(text, func(match string) string {
		name := placeholder.FindStringSubmatch(match)[1]
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
	match := placeholder.FindStringSubmatch(s)
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

// decodeParams decodes the call's parameters for substitution. The Validator
// held them to the operation's schema — the declared types, the required ones
// present, and no others — so only an integer needs converting from JSON's
// float.
func decodeParams(operation Operation, raw json.RawMessage) (map[string]any, error) {
	var params map[string]any
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, fmt.Errorf("decode parameters: %w", err)
	}
	// The `operation` discriminator selects the case. It is not a parameter.
	delete(params, "operation")
	for name, value := range params {
		if operation.Params[name].Type == "integer" {
			params[name] = int64(value.(float64))
		}
	}
	return params, nil
}
