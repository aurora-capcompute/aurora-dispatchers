// Package builtin routes one process's leaf syscalls to the handler that serves
// them. It is the bottom of the dispatcher chain and knows nothing about any
// particular capability: a driver publishes a Handler and a sys.Capability, and
// this package picks between them by name.
package builtin

import (
	"context"

	"github.com/aurora-capcompute/capcompute/sys"
)

// Handler serves one capability. Drivers implement it in their own packages;
// Go's interfaces are structural, so none of them needs to import this one.
type Handler interface {
	Handles(name string) bool
	DispatchCall(ctx context.Context, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error)
}

// Config is what a registry assembles for one process: the handlers it may
// reach and the capabilities they advertise. The advertised set is what the
// runtime's Validator will admit — see reconcileGrants — so a handler without a
// capability is unreachable, and a capability without a handler fails closed at
// Dispatch.
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
