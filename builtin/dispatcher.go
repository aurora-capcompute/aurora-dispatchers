package builtin

import (
	"github.com/aurora-capcompute/aurora-dispatchers/internet"
	"github.com/aurora-capcompute/aurora-dispatchers/mcp"
	"github.com/aurora-capcompute/aurora-dispatchers/resolution"
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
	DispatchCall(ctx context.Context, call dispatcher.Call) (dispatcher.Outcome, error)
}

type Config struct {
	Internet                InternetReader
	InternetRequireApproval bool
	MCP                     []*mcp.Handler
	Handlers                []Handler
	Capabilities            []dispatcher.Capability
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

func (d *Dispatcher[K]) Dispatch(ctx context.Context, _ K, call dispatcher.Call) (dispatcher.Outcome, error) {
	switch call.Name {
	case "internet.read":
		if d.Internet == nil {
			return dispatcher.Failed("internet reader is not configured"), nil
		}
		var request internet.ReadRequest
		if err := json.Unmarshal(call.Args, &request); err != nil {
			return dispatcher.Failed(fmt.Sprintf("decode internet.read request: %v", err)), nil
		}
		if d.InternetRequireApproval {
			if resolved, ok := resolution.FromContext(ctx); !ok || resolved.Decision != resolution.Approved {
				return dispatcher.Yield(fmt.Sprintf("Approve %s %s", request.Method, request.URL)), nil
			}
		}
		response, err := d.Internet.Read(ctx, request)
		if err != nil {
			if ctx.Err() != nil {
				return dispatcher.Outcome{}, ctx.Err()
			}
			return dispatcher.Failed(err.Error()), nil
		}
		return marshalResult(response)

	default:
		for _, handler := range d.MCP {
			if handler.Handles(call.Name) {
				return handler.DispatchCall(ctx, call)
			}
		}
		for _, handler := range d.Handlers {
			if handler.Handles(call.Name) {
				return handler.DispatchCall(ctx, call)
			}
		}
		return dispatcher.Failed("unknown call: " + call.Name), nil
	}
}

func marshalResult(value any) (dispatcher.Outcome, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return dispatcher.Outcome{}, err
	}
	return dispatcher.Result(raw), nil
}
