package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/aurora-capcompute/aurora-dispatchers/internet"
	"github.com/aurora-capcompute/capcompute/sys"
)

type InternetClient interface {
	Do(context.Context, internet.Request) (internet.Response, error)
}

type Handler interface {
	Handles(name string) bool
	DispatchCall(ctx context.Context, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error)
}

type Config struct {
	Handlers     []Handler
	Capabilities []sys.Capability
}

type Dispatcher[K any] struct {
	Config
}

func New[K any](config Config) sys.Dispatcher[K] {
	return &Dispatcher[K]{Config: config}
}

func (d *Dispatcher[K]) Capabilities() []sys.Capability {
	return d.Config.Capabilities
}

// Dispatch routes a program call to the handler that owns its name. Every tool is
// addressed by its local manifest name; there are no fixed capability names.
func (d *Dispatcher[K]) Dispatch(ctx context.Context, _ K, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	for _, handler := range d.Handlers {
		if handler.Handles(call.Name) {
			return handler.DispatchCall(ctx, call, auth)
		}
	}
	return sys.FailCode(sys.ErrnoNotFound, "unknown call: "+call.Name), nil
}

// InternetHandler adapts an InternetClient to the Handler interface, bound to
// the published capability name (core.internet). Its allowlist lives in the
// client's Policy; the per-method policy here is the grant's data-flow and
// approval declaration, resolved from the call's HTTP method — the method is the
// ADT discriminator of a single net capability.
type InternetHandler struct {
	Name string
	// Methods is the per-method policy keyed by uppercase HTTP method, with "*"
	// applying to every method; the two are merged for the request's method.
	Methods map[string]InternetMethodPolicy
	Client  InternetClient
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
		if m == internet.AnyMethod || strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

// InternetMethodPolicy is one HTTP method's grant policy: whether the request
// needs human approval, the source classes its response carries (Labels), and
// the labels barred from flowing into the request (Taints, the sink guard).
type InternetMethodPolicy struct {
	RequireApproval bool
	Labels          []string
	Taints          []string
}

func (h InternetHandler) Handles(name string) bool { return name == h.Name }

func (h InternetHandler) DispatchCall(ctx context.Context, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if h.Client == nil {
		return sys.FailCode(sys.ErrnoNotFound, "internet client is not configured"), nil
	}
	var request internet.Request
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
	credentialLabels := h.inject(&request, method)

	response, err := h.Client.Do(ctx, request)
	if err != nil {
		if ctx.Err() != nil {
			return sys.SyscallResult{}, ctx.Err()
		}
		// A failed attempt still records which credential it carried.
		return sys.FailCode(sys.ErrnoTransient, err.Error()).WithLabels(credentialLabels...), nil
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
func (h InternetHandler) inject(request *internet.Request, method string) []string {
	if len(h.Injections) == 0 {
		return nil
	}
	host := requestHost(request.URL)
	if host == "" {
		return nil
	}
	var labels []string
	for _, rule := range h.Injections {
		if !rule.applies(method, host) {
			continue
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
		}
		labels = append(labels, rule.Labels...)
	}
	return labels
}

func requestHost(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Host == "" {
		return ""
	}
	return strings.ToLower(parsed.Host)
}

// methodPolicy merges the wildcard ("*") policy with the request method's own —
// the union of their approval requirement and label sets.
func (h InternetHandler) methodPolicy(method string) InternetMethodPolicy {
	wild := h.Methods["*"]
	specific := h.Methods[method]
	return InternetMethodPolicy{
		RequireApproval: wild.RequireApproval || specific.RequireApproval,
		Labels:          UnionLabels(wild.Labels, specific.Labels),
		Taints:          UnionLabels(wild.Taints, specific.Taints),
	}
}

// UnionLabels concatenates two already-normalized label sets, dropping
// duplicates. Order is not significant for flow decisions or result labels
// (WithLabels re-sorts).
func UnionLabels(a, b []string) []string {
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
