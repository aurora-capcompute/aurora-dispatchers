package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aurora-capcompute/aurora-dispatchers/internet"
	"github.com/aurora-capcompute/aurora-dispatchers/mcp"
	"github.com/aurora-capcompute/capcompute/sys"
)

type InternetReader interface {
	Read(context.Context, internet.ReadRequest) (internet.ReadResponse, error)
}

type Handler interface {
	Handles(name string) bool
	DispatchCall(ctx context.Context, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error)
}

type Config struct {
	Internet                InternetReader
	InternetRequireApproval bool
	MCP                     []*mcp.Handler
	Handlers                []Handler
	Capabilities            []sys.Capability
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

func (d *Dispatcher[K]) Dispatch(ctx context.Context, _ K, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	switch call.Name {
	case "internet.read":
		if d.Internet == nil {
			return sys.Fail("internet reader is not configured"), nil
		}
		var request internet.ReadRequest
		if err := json.Unmarshal(call.Args, &request); err != nil {
			return sys.Fail(fmt.Sprintf("decode internet.read request: %v", err)), nil
		}
		if d.InternetRequireApproval {
			if auth.Decision != sys.Approved {
				return sys.Yield(fmt.Sprintf("Approve %s %s", request.Method, request.URL)), nil
			}
		}
		response, err := d.Internet.Read(ctx, request)
		if err != nil {
			if ctx.Err() != nil {
				return sys.SyscallResult{}, ctx.Err()
			}
			return sys.Fail(err.Error()), nil
		}
		return marshalResult(response)

	default:
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
		return sys.Fail("unknown call: " + call.Name), nil
	}
}

func marshalResult(value any) (sys.SyscallResult, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return sys.SyscallResult{}, err
	}
	return sys.Result(raw), nil
}
