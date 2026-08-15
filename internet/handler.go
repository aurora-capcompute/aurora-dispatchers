package internet

// The core.internet capability's dispatcher half: the Handler a leaf chain
// routes a call to, and the host-held credentials it may attach. The policy it
// enforces is this package's Policy, checked again by the Client — being granted
// core.internet is not being granted the internet.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/aurora-capcompute/capcompute/sys"
)

// Doer is the client half a Handler needs: the concrete *Client satisfies it,
// and a test double can stand in.
type Doer interface {
	Do(context.Context, Request) (Response, error)
}

// Handler adapts an Doer to the Handler interface, bound to
// the published capability name (core.internet). Its allowlist lives in the
// client's Policy; the per-method policy here is the grant's data-flow and
// approval declaration, resolved from the call's HTTP method — the method is the
// ADT discriminator of a single net capability.
type Handler struct {
	Name string
	// Methods is the per-method policy keyed by uppercase HTTP method, with "*"
	// applying to every method; the two are merged for the request's method.
	Methods map[string]MethodPolicy
	Client  Doer
	// Injections attach host-held credential headers to matching (method, host)
	// requests. The header values are resolved host-side and are never supplied
	// by, visible to, or overridable by the guest.
	Injections []CredentialInjection
}

// CredentialInjection attaches host-held headers to outbound requests whose
// method and host it matches. It is bound to a specific host (never a wildcard)
// and — by construction at build time — only to https or loopback origins, so a
// credential cannot be sent in the clear or to an unintended host. The guest
// never sees Headers and cannot override them (host wins). Labels are stamped on
// the result so the journal records which credential was used, never the value.
type CredentialInjection struct {
	Methods []string          // uppercase HTTP methods, or ["*"] for any
	Host    string            // lowercased request host[:port] this applies to
	Headers map[string]string // header name -> full host-held value
	Labels  []string          // provenance labels stamped when applied
}

func (c CredentialInjection) applies(method, host string) bool {
	if !strings.EqualFold(c.Host, host) {
		return false
	}
	for _, m := range c.Methods {
		if m == AnyMethod || strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

// MethodPolicy is one HTTP method's grant policy: whether the request
// needs human approval, the source classes its response carries (Labels), and
// the labels barred from flowing into the request (Taints, the sink guard).
type MethodPolicy struct {
	RequireApproval bool
	Labels          []string
	Taints          []string
}

func (h Handler) Handles(name string) bool { return name == h.Name }

func (h Handler) DispatchCall(ctx context.Context, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if h.Client == nil {
		return sys.FailCode(sys.ErrnoNotFound, "internet client is not configured"), nil
	}
	var request Request
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", h.Name, err)), nil
	}
	method := strings.ToUpper(strings.TrimSpace(request.Method))
	policy := h.methodPolicy(method)
	// Sink guard: refuse before the request leaves if the run has observed a
	// label this method forbids.
	if blocked := sys.BlockedBy(sys.Taint(ctx), policy.Taints); len(blocked) > 0 {
		return sys.FailCode(sys.ErrnoDenied, fmt.Sprintf(
			"flow policy: this run has observed %v, which may not flow into a %s request", blocked, method)), nil
	}
	if policy.RequireApproval && auth.Decision != sys.Approved {
		return sys.Yield(fmt.Sprintf("Approve %s %s", request.Method, request.URL)), nil
	}

	// Attach any host-held credential for this (method, host). Host wins over a
	// guest header of the same name, so the guest can neither read nor override
	// it; the value is never in the call args, so it never reaches the journaled
	// intent. The returned labels name the credential (not its value) for audit.
	credentialLabels, binding, err := h.inject(&request, method)
	if err != nil {
		return sys.FailCode(sys.ErrnoDenied, err.Error()), nil
	}
	reqCtx := ctx
	if len(binding.headers) > 0 {
		// Bind the credential to this request's origin so the client drops it on
		// any redirect that leaves that origin.
		reqCtx = WithInjectedCredential(ctx, binding.origin, binding.headers)
	}

	response, err := h.Client.Do(reqCtx, request)
	if err != nil {
		if ctx.Err() != nil {
			return sys.SyscallResult{}, ctx.Err()
		}
		// A failed attempt still carries the operation's source labels AND its
		// credential provenance: the error text is derived from the request to a
		// labeled source (e.g. a redirect target host echoed by the allowlist
		// check), so taint the run as if the read happened. Conservative — an
		// attempted read of a labeled source taints, closing an error-channel
		// launder where a failed fetch's message flows to a forbidding sink
		// untainted.
		return sys.FailCode(sys.ErrnoTransient, err.Error()).WithLabels(
			append(append([]string(nil), policy.Labels...), credentialLabels...)...), nil
	}
	result, err := marshalResult(response)
	if err != nil {
		return result, err
	}
	// The response derives from the network: stamp the method's source labels and
	// the credential provenance.
	return result.WithLabels(append(append([]string(nil), policy.Labels...), credentialLabels...)...), nil
}

// inject attaches matching credential headers to the request (host wins over a
// guest-supplied header) and returns the provenance labels to stamp on the
// result. The injected values are host-held and never echoed to the guest.
// credentialBinding is the origin a request's injected credential is bound to,
// plus the header names carrying it — handed to the internet client so a
// redirect leaving the origin drops them before they reach another host.
type credentialBinding struct {
	origin  string
	headers []string
}

func (h Handler) inject(request *Request, method string) ([]string, credentialBinding, error) {
	if len(h.Injections) == 0 {
		return nil, credentialBinding{}, nil
	}
	parsed, err := url.Parse(strings.TrimSpace(request.URL))
	if err != nil || parsed.Host == "" {
		return nil, credentialBinding{}, nil
	}
	host := strings.ToLower(parsed.Host)
	var labels []string
	var injected []string
	for _, rule := range h.Injections {
		if !rule.applies(method, host) {
			continue
		}
		// A host-held credential rides only TLS (loopback exempt). The manifest
		// gate proved the declared origin is https; re-assert it against the
		// actual request scheme so an http:// request to the bound host cannot
		// downgrade the credential onto a plaintext wire a network observer reads.
		if !strings.EqualFold(parsed.Scheme, "https") && !LoopbackHost(host) {
			return nil, credentialBinding{}, fmt.Errorf("refusing to attach a host-held credential to a non-https request to %s", host)
		}
		if request.Headers == nil {
			request.Headers = make(map[string]string, len(rule.Headers))
		}
		for name, value := range rule.Headers {
			// Host wins over any guest header of the same name — whatever casing
			// the guest used. rule.Headers keys are canonical; drop every guest key
			// that canonicalizes to the same name before setting the host's, so a
			// guest "authorization" cannot survive alongside the host "Authorization"
			// (two map keys net/http would then apply in nondeterministic order).
			for existing := range request.Headers {
				if http.CanonicalHeaderKey(existing) == name {
					delete(request.Headers, existing)
				}
			}
			request.Headers[name] = value
			injected = append(injected, name)
		}
		labels = append(labels, rule.Labels...)
	}
	binding := credentialBinding{}
	if len(injected) > 0 {
		binding = credentialBinding{origin: OriginOf(parsed), headers: injected}
	}
	return labels, binding, nil
}

// methodPolicy merges the wildcard ("*") policy with the request method's own —
// the union of their approval requirement and label sets.
func (h Handler) methodPolicy(method string) MethodPolicy {
	wild := h.Methods["*"]
	specific := h.Methods[method]
	return MethodPolicy{
		RequireApproval: wild.RequireApproval || specific.RequireApproval,
		Labels:          unionLabels(wild.Labels, specific.Labels),
		Taints:          unionLabels(wild.Taints, specific.Taints),
	}
}

// unionLabels concatenates two already-normalized label sets, dropping
// duplicates. Order is not significant for flow decisions or result labels
// (WithLabels re-sorts).
func unionLabels(a, b []string) []string {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, label := range append(append([]string(nil), a...), b...) {
		if _, dup := seen[label]; dup {
			continue
		}
		seen[label] = struct{}{}
		out = append(out, label)
	}
	return out
}

func marshalResult(value any) (sys.SyscallResult, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return sys.SyscallResult{}, err
	}
	return sys.Result(raw), nil
}
