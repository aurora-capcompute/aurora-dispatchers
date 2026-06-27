package timer_test

import (
	"github.com/aurora-capcompute/capcompute/dispatcher"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-dispatchers/timer"
)

func dispatch(t *testing.T, h timer.Handler, args string) dispatcher.Outcome {
	t.Helper()
	outcome, err := h.DispatchCall(context.Background(), dispatcher.Call{
		Name: "timer.set",
		Args: json.RawMessage(args),
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	return outcome
}

func TestValidRequestYields(t *testing.T) {
	outcome := dispatch(t, timer.Handler{}, `{"duration_seconds":1800,"label":"remind"}`)
	if outcome.Kind() != dispatcher.OutcomeYield {
		t.Fatalf("kind = %q, want yield", outcome.Kind())
	}
	if outcome.Message() == "" {
		t.Fatal("expected a yield summary")
	}
}

func TestNonPositiveDurationFails(t *testing.T) {
	for _, args := range []string{`{"duration_seconds":0}`, `{"duration_seconds":-5}`} {
		outcome := dispatch(t, timer.Handler{}, args)
		if outcome.Kind() != dispatcher.OutcomeFailed {
			t.Fatalf("args %s: kind = %q, want failed", args, outcome.Kind())
		}
	}
}

func TestDurationOverMaxFails(t *testing.T) {
	h := timer.Handler{MaxDuration: time.Minute}
	outcome := dispatch(t, h, `{"duration_seconds":120}`)
	if outcome.Kind() != dispatcher.OutcomeFailed {
		t.Fatalf("kind = %q, want failed", outcome.Kind())
	}
}

func TestInvalidJSONFails(t *testing.T) {
	outcome := dispatch(t, timer.Handler{}, `not json`)
	if outcome.Kind() != dispatcher.OutcomeFailed {
		t.Fatalf("kind = %q, want failed", outcome.Kind())
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
