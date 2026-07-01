package builtin

import (
	"github.com/aurora-capcompute/aurora-dispatchers/internet"
	"github.com/aurora-capcompute/aurora-dispatchers/mcp"
	"github.com/aurora-capcompute/capcompute/dispatcher"
	"context"
	"encoding/json"
	"fmt"
)

type InternetReader interface {
	Read(context.Context, internet.ReadRequest) (internet.ReadResponse, error)
}

type Handler interface {
	Handles(name string) bool
	DispatchCall(ctx context.Context, call dispatcher.Call, auth dispatcher.Authorization) (dispatcher.Outcome, error)
}

type Config struct {
	MCP          []*mcp.Handler
	Handlers     []Handler
	Capabilities []dispatcher.Capability
}

type Dispatcher[K any] struct {
	Config
}

func New[K any](config Config) dispatcher.Dispatcher[K] {
	return &Dispatcher[K]{Config: config}
}

func (d *Dispatcher[K]) Capabilities() []dispatcher.Capability {
	return d.Config.Capabilities
}

// Dispatch routes a brain call to the handler that owns its name. Every tool is
// addressed by its local manifest name; there are no fixed capability names.
func (d *Dispatcher[K]) Dispatch(ctx context.Context, _ K, call dispatcher.Call, auth dispatcher.Authorization) (dispatcher.Outcome, error) {
	for _, handler := range d.MCP {
		if handler.Handles(call.Name) {
			return handler.DispatchCall(ctx, call, auth)
		}
	}
	for _, handler := range d.Handlers {
		if handler.Handles(call.Name) {
			return handler.DispatchCall(ctx, call, auth)
		}
	}
	return dispatcher.Fail("unknown call: " + call.Name), nil
}

// InternetHandler adapts an InternetReader to the Handler interface, bound to a
// tool's local name. It carries the per-tool require-approval policy.
type InternetHandler struct {
	Name            string
	Reader          InternetReader
	RequireApproval bool
}

func (h InternetHandler) Handles(name string) bool { return name == h.Name }

func (h InternetHandler) DispatchCall(ctx context.Context, call dispatcher.Call, auth dispatcher.Authorization) (dispatcher.Outcome, error) {
	if h.Reader == nil {
		return dispatcher.Fail("internet reader is not configured"), nil
	}
	var request internet.ReadRequest
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return dispatcher.Fail(fmt.Sprintf("decode %s request: %v", h.Name, err)), nil
	}
	if h.RequireApproval && auth.Decision != dispatcher.Approved {
		return dispatcher.Yield(fmt.Sprintf("Approve %s %s", request.Method, request.URL)), nil
	}
	response, err := h.Reader.Read(ctx, request)
	if err != nil {
		if ctx.Err() != nil {
			return dispatcher.Outcome{}, ctx.Err()
		}
		return dispatcher.Fail(err.Error()), nil
	}
	return marshalResult(response)
}

func marshalResult(value any) (dispatcher.Outcome, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return dispatcher.Outcome{}, err
	}
	return dispatcher.Result(raw), nil
}
