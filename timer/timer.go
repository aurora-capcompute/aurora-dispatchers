// Package timer provides the timer.set capability. The capability lets a guest
// agent schedule a relative-duration timer and be replayed when it fires.
//
// timer.set always yields a durable task. The host application owns a scheduler
// that resolves the task (with Completed) once the requested duration elapses,
// which resumes the run from the same point. The handler is therefore only ever
// invoked for the initial yield; on resume the resolved task data is returned
// directly by the task dispatcher without re-dispatching here.
package timer

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aurora-capcompute/capcompute/sys"
	"time"
)

// Capability is the guest-callable name for the timer.
const Capability = "timer.set"

// DefaultMaxDuration bounds how far in the future a timer may be set. It guards
// against unbounded waits and keeps timers within any task expiry window the
// host configures.
const DefaultMaxDuration = 24 * time.Hour

// SetRequest is the guest payload for timer.set.
type SetRequest struct {
	DurationSeconds int64  `json:"duration_seconds"`
	Label           string `json:"label,omitempty"`
}

// Handler dispatches a timer tool's calls. It satisfies builtin.Handler and is
// bound to the tool's local manifest name.
type Handler struct {
	// Name is the tool's local manifest name the brain dispatches to.
	Name string
	// MaxDuration bounds the requested duration. Zero uses DefaultMaxDuration.
	MaxDuration time.Duration
}

// Handles reports whether the handler owns the given local tool name.
func (h Handler) Handles(name string) bool { return name == h.Name }

// DispatchCall validates the request and yields a durable task. A valid call
// always yields; invalid input fails immediately so the agent gets feedback.
func (h Handler) DispatchCall(_ context.Context, call sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	var request SetRequest
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode timer.set request: %v", err)), nil
	}
	if request.DurationSeconds <= 0 {
		return sys.FailCode(sys.ErrnoInvalidArgs, "duration_seconds must be positive"), nil
	}
	max := h.MaxDuration
	if max <= 0 {
		max = DefaultMaxDuration
	}
	if time.Duration(request.DurationSeconds)*time.Second > max {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("duration_seconds must be at most %d", int64(max/time.Second))), nil
	}
	duration := time.Duration(request.DurationSeconds) * time.Second
	if request.Label != "" {
		return sys.Yield(fmt.Sprintf("Timer for %s: %s", duration, request.Label)), nil
	}
	return sys.Yield(fmt.Sprintf("Timer for %s", duration)), nil
}
