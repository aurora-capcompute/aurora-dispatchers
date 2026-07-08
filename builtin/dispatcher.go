package builtin

import (
	"context"
	"encoding/json"
	"fmt"
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
	response, err := h.Client.Do(ctx, request)
	if err != nil {
		if ctx.Err() != nil {
			return sys.SyscallResult{}, ctx.Err()
		}
		return sys.FailCode(sys.ErrnoTransient, err.Error()), nil
	}
	result, err := marshalResult(response)
	if err != nil {
		return result, err
	}
	// The response derives from the network: stamp the method's source labels.
	return result.WithLabels(policy.Labels...), nil
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
