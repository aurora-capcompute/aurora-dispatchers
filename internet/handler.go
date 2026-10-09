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
	"slices"
	"strings"

	"github.com/aurora-capcompute/capcompute/sys"
)

// Doer is the client half a Handler needs: the concrete *Client satisfies it,
// and a test double can stand in.
type Doer interface {
	Do(context.Context, Request) (Response, error)
}

// Handler serves core.internet calls through a Doer. Its allowlist lives in the
// client's Policy. The per-method data-flow and approval policy is the entry's,
// resolved from the call's HTTP method — the method is the ADT discriminator of
// a single net capability.
type Handler struct {
	Client Doer
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
	Methods []string          // uppercase HTTP methods
	Host    string            // lowercased request host[:port] this applies to
	Headers map[string]string // header name -> full host-held value
	Labels  []string          // provenance labels stamped when applied
}

func (c CredentialInjection) applies(method, host string) bool {
	return c.Host == host && slices.Contains(c.Methods, method)
}

// MethodPolicy is one HTTP method's grant policy, carried from the manifest to
// that method's entry. Nothing here enforces it — the runtime does, above and
// below the replay tape: whether the request needs human approval, the source
// classes its response carries (Labels), and the labels barred from flowing into
// the request (Taints, the sink guard).
type MethodPolicy struct {
	RequireApproval bool
	Labels          []string
	Taints          []string
}

func (h Handler) DispatchCall(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error) {
	var request Request
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", call.Name, err)), nil
	}
	// Attach any host-held credential for this (method, host). Host wins over a
	// guest header of the same name, so the guest can neither read nor override
	// it. The value is never in the call args, so it never reaches the journaled
	// intent. The returned labels name the credential (not its value) for audit.
	credentialLabels, binding, err := h.inject(&request)
	if err != nil {
		return sys.FailCode(sys.ErrnoDenied, err.Error()), nil
	}
	if len(binding.headers) > 0 {
		// Bind the credential to this request's origin so the client drops it on
		// any redirect that leaves that origin.
		ctx = WithInjectedCredential(ctx, binding.origin, binding.headers)
	}

	response, err := h.Client.Do(ctx, request)
	if err != nil {
		if ctx.Err() != nil {
			return sys.SyscallResult{}, ctx.Err()
		}
		// The credential provenance is dynamic — which injection matched depends
		// on the request's host — so it is stamped here rather than declared on
		// the entry. A failed attempt carries it too: its error text derives from
		// a request made with that credential. The monitor stamps the method's
		// own source labels.
		return sys.FailCode(sys.ErrnoTransient, err.Error()).WithLabels(credentialLabels...), nil
	}
	result, err := marshalResult(response)
	if err != nil {
		return result, err
	}
	return result.WithLabels(credentialLabels...), nil
}

// credentialBinding is the origin a request's injected credential is bound to,
// plus the header names carrying it — handed to the internet client so a
// redirect leaving the origin drops them before they reach another host.
type credentialBinding struct {
	origin  string
	headers []string
}

// inject attaches matching credential headers to the request (host wins over a
// guest-supplied header) and returns the provenance labels to stamp on the
// result. The injected values are host-held and never echoed to the guest.
func (h Handler) inject(request *Request) ([]string, credentialBinding, error) {
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
		if !rule.applies(request.Method, host) {
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

func marshalResult(value any) (sys.SyscallResult, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return sys.SyscallResult{}, err
	}
	return sys.Result(raw), nil
}
