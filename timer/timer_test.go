package timer_test

import (
	"context"
	"encoding/json"
	"github.com/aurora-capcompute/capcompute/sys"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-dispatchers/timer"
)

func dispatch(t *testing.T, h timer.Handler, args string) sys.SyscallResult {
	t.Helper()
	outcome, err := h.DispatchCall(context.Background(), sys.Syscall{
		Name: "timer.set",
		Args: json.RawMessage(args),
	}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	return outcome
}

func TestValidRequestYields(t *testing.T) {
	outcome := dispatch(t, timer.Handler{}, `{"duration_seconds":1800,"label":"remind"}`)
	if outcome.Status() != sys.StatusYield {
		t.Fatalf("kind = %q, want yield", outcome.Status())
	}
	if outcome.Message() == "" {
		t.Fatal("expected a yield summary")
	}
}

func TestNonPositiveDurationFails(t *testing.T) {
	for _, args := range []string{`{"duration_seconds":0}`, `{"duration_seconds":-5}`} {
		outcome := dispatch(t, timer.Handler{}, args)
		if outcome.Status() != sys.StatusFailed {
			t.Fatalf("args %s: kind = %q, want failed", args, outcome.Status())
		}
	}
}

func TestDurationOverMaxFails(t *testing.T) {
	h := timer.Handler{MaxDuration: time.Minute}
	outcome := dispatch(t, h, `{"duration_seconds":120}`)
	if outcome.Status() != sys.StatusFailed {
		t.Fatalf("kind = %q, want failed", outcome.Status())
	}
}

func TestInvalidJSONFails(t *testing.T) {
	outcome := dispatch(t, timer.Handler{}, `not json`)
	if outcome.Status() != sys.StatusFailed {
		t.Fatalf("kind = %q, want failed", outcome.Status())
	}
}

func TestHandles(t *testing.T) {
	h := timer.Handler{}
	if !h.Handles("timer.set") {
		t.Fatal("should handle timer.set")
	}
	if h.Handles("internet.read") {
		t.Fatal("should not handle internet.read")
	}
}
