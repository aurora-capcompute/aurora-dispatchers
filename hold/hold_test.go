package hold_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-dispatchers/hold"
	"github.com/aurora-capcompute/capcompute/sys"
)

func dispatch(t *testing.T, h *hold.Handler, name, args string) sys.SyscallResult {
	t.Helper()
	return dispatchCtx(t, context.Background(), h, name, args)
}

func dispatchCtx(t *testing.T, ctx context.Context, h *hold.Handler, name, args string) sys.SyscallResult {
	t.Helper()
	call := sys.Syscall{Abi: sys.ABIVersion, Name: name}
	if args != "" {
		call.Args = json.RawMessage(args)
	}
	result, err := h.DispatchCall(ctx, call, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch %s: %v", name, err)
	}
	return result
}

func reserved(t *testing.T, result sys.SyscallResult) hold.ReserveResponse {
	t.Helper()
	if result.Status() != sys.StatusResult {
		t.Fatalf("reserve = %#v, want result", result)
	}
	var response hold.ReserveResponse
	if err := json.Unmarshal(result.Result(), &response); err != nil {
		t.Fatalf("decode reserve response: %v", err)
	}
	return response
}

// sequenceIDs is a deterministic hold-id source for tests.
func sequenceIDs(minted *int) func() (string, error) {
	return func() (string, error) {
		*minted++
		return fmt.Sprintf("hold-%d", *minted), nil
	}
}

// The Try-Confirm happy path: reserve places a PENDING hold with the default
// deadline, confirm makes it permanent, re-confirming is idempotent, and a
// confirmed hold keeps the resource forever — the pending deadline no longer
// applies.
func TestHoldReserveConfirmHappyPath(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	minted := 0
	h := &hold.Handler{Name: "inv", Now: func() time.Time { return now }, NewID: sequenceIDs(&minted)}

	response := reserved(t, dispatch(t, h, "inv.reserve", `{"resource":"seat-1A"}`))
	if response.HoldID != "hold-1" || response.Resource != "seat-1A" {
		t.Fatalf("reserve = %+v", response)
	}
	if response.ExpiresAtMS != now.Add(hold.DefaultTTL).UnixMilli() {
		t.Fatalf("expires_at_ms = %d, want the default %s window", response.ExpiresAtMS, hold.DefaultTTL)
	}

	confirm := dispatch(t, h, "inv.confirm", `{"hold_id":"hold-1"}`)
	if confirm.Status() != sys.StatusResult || string(confirm.Result()) != `{"confirmed":true}` {
		t.Fatalf("confirm = %#v", confirm)
	}
	// Confirming a confirmed hold succeeds — the Confirm leg is idempotent.
	again := dispatch(t, h, "inv.confirm", `{"hold_id":"hold-1"}`)
	if again.Status() != sys.StatusResult || string(again.Result()) != string(confirm.Result()) {
		t.Fatalf("re-confirm = %#v, want the same success", again)
	}

	// Confirmed means kept: far past the pending deadline the resource stays taken.
	now = now.Add(48 * time.Hour)
	if result := dispatch(t, h, "inv.reserve", `{"resource":"seat-1A"}`); result.Errno() != sys.ErrnoConflict {
		t.Fatalf("reserve of a confirmed resource = %#v, want conflict", result)
	}
}

// Saga isolation: a live pending hold blocks a second reservation of the same
// resource, other resources stay free, and a release frees the held one.
func TestHoldDoubleReserveConflicts(t *testing.T) {
	h := &hold.Handler{Name: "inv"}

	first := reserved(t, dispatch(t, h, "inv.reserve", `{"resource":"seat-1A"}`))
	if second := dispatch(t, h, "inv.reserve", `{"resource":"seat-1A"}`); second.Status() != sys.StatusFailed || second.Errno() != sys.ErrnoConflict {
		t.Fatalf("double reserve = %#v, want failed/conflict", second)
	}
	// Conflicts are per resource.
	reserved(t, dispatch(t, h, "inv.reserve", `{"resource":"seat-2B"}`))

	// Release (the Cancel leg) frees the resource for the next reservation.
	if result := dispatch(t, h, "inv.release", `{"hold_id":"`+first.HoldID+`"}`); result.Status() != sys.StatusResult {
		t.Fatalf("release = %#v", result)
	}
	reserved(t, dispatch(t, h, "inv.reserve", `{"resource":"seat-1A"}`))
}

// Lazy expiry, confirm-first: at the deadline the Try is void — confirm fails
// with errno expired, the lapsed hold is purged, and the resource is
// reservable again. Unknown and purged ids report not_found.
func TestHoldExpiryFailsConfirmAndFreesResource(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	h := &hold.Handler{Name: "inv", Now: func() time.Time { return now }}

	response := reserved(t, dispatch(t, h, "inv.reserve", `{"resource":"seat-1A","ttl_seconds":60}`))
	if response.ExpiresAtMS != now.Add(60*time.Second).UnixMilli() {
		t.Fatalf("expires_at_ms = %d, want now+60s", response.ExpiresAtMS)
	}

	// The deadline itself is already past due (expires_at_ms is the instant
	// the hold lapses).
	now = now.Add(60 * time.Second)
	confirm := dispatch(t, h, "inv.confirm", `{"hold_id":"`+response.HoldID+`"}`)
	if confirm.Status() != sys.StatusFailed || confirm.Errno() != sys.ErrnoExpired {
		t.Fatalf("confirm past deadline = %#v, want failed/expired", confirm)
	}

	// The lapsed hold no longer blocks the resource…
	reserved(t, dispatch(t, h, "inv.reserve", `{"resource":"seat-1A"}`))
	// …and its id is purged: a second confirm reports not_found, like ids
	// that never existed.
	if result := dispatch(t, h, "inv.confirm", `{"hold_id":"`+response.HoldID+`"}`); result.Errno() != sys.ErrnoNotFound {
		t.Fatalf("confirm of purged hold = %#v, want not_found", result)
	}
	if result := dispatch(t, h, "inv.confirm", `{"hold_id":"never-was"}`); result.Errno() != sys.ErrnoNotFound {
		t.Fatalf("confirm of unknown hold = %#v, want not_found", result)
	}
}

// Lazy expiry, reserve-first: a reserve that finds an expired pending hold on
// its resource purges it and takes its place.
func TestHoldReserveLazilyPurgesExpiredHold(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	minted := 0
	h := &hold.Handler{Name: "inv", Now: func() time.Time { return now }, NewID: sequenceIDs(&minted)}

	first := reserved(t, dispatch(t, h, "inv.reserve", `{"resource":"seat-1A","ttl_seconds":60}`))
	now = now.Add(61 * time.Second)
	second := reserved(t, dispatch(t, h, "inv.reserve", `{"resource":"seat-1A"}`))
	if second.HoldID == first.HoldID {
		t.Fatalf("re-reserve reused hold id %q", second.HoldID)
	}
	// The purged first hold is gone; the fresh one confirms.
	if result := dispatch(t, h, "inv.confirm", `{"hold_id":"`+first.HoldID+`"}`); result.Errno() != sys.ErrnoNotFound {
		t.Fatalf("confirm of purged hold = %#v, want not_found", result)
	}
	if result := dispatch(t, h, "inv.confirm", `{"hold_id":"`+second.HoldID+`"}`); result.Status() != sys.StatusResult {
		t.Fatalf("confirm of fresh hold = %#v", result)
	}
}

// The Cancel leg is an undo, and an undo must never fail for being already
// undone: releasing pending, released, expired, and unknown holds all
// succeed with the same response.
func TestHoldReleaseIsIdempotent(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	h := &hold.Handler{Name: "inv", Now: func() time.Time { return now }}

	response := reserved(t, dispatch(t, h, "inv.reserve", `{"resource":"seat-1A","ttl_seconds":60}`))
	release := dispatch(t, h, "inv.release", `{"hold_id":"`+response.HoldID+`"}`)
	if release.Status() != sys.StatusResult || string(release.Result()) != `{"released":true}` {
		t.Fatalf("release = %#v", release)
	}
	// Already released: succeeds again, byte-identically.
	again := dispatch(t, h, "inv.release", `{"hold_id":"`+response.HoldID+`"}`)
	if again.Status() != sys.StatusResult || string(again.Result()) != string(release.Result()) {
		t.Fatalf("re-release = %#v, want the same success", again)
	}
	// Unknown ids: the undo's work is already done.
	if result := dispatch(t, h, "inv.release", `{"hold_id":"never-was"}`); result.Status() != sys.StatusResult {
		t.Fatalf("release of unknown hold = %#v, want success", result)
	}

	// Expired holds release cleanly too, and the resource stays reservable.
	expiring := reserved(t, dispatch(t, h, "inv.reserve", `{"resource":"seat-1A","ttl_seconds":60}`))
	now = now.Add(61 * time.Second)
	if result := dispatch(t, h, "inv.release", `{"hold_id":"`+expiring.HoldID+`"}`); result.Status() != sys.StatusResult {
		t.Fatalf("release of expired hold = %#v, want success", result)
	}
	reserved(t, dispatch(t, h, "inv.reserve", `{"resource":"seat-1A"}`))
}

// Confirmed means kept: the Confirm leg converts the hold into the outcome,
// so the Cancel leg refuses it with a conflict and the resource stays taken.
func TestHoldConfirmedHoldRefusesRelease(t *testing.T) {
	h := &hold.Handler{Name: "inv"}

	response := reserved(t, dispatch(t, h, "inv.reserve", `{"resource":"seat-1A"}`))
	if result := dispatch(t, h, "inv.confirm", `{"hold_id":"`+response.HoldID+`"}`); result.Status() != sys.StatusResult {
		t.Fatalf("confirm = %#v", result)
	}
	release := dispatch(t, h, "inv.release", `{"hold_id":"`+response.HoldID+`"}`)
	if release.Status() != sys.StatusFailed || release.Errno() != sys.ErrnoConflict {
		t.Fatalf("release of confirmed hold = %#v, want failed/conflict", release)
	}
	if result := dispatch(t, h, "inv.reserve", `{"resource":"seat-1A"}`); result.Errno() != sys.ErrnoConflict {
		t.Fatalf("confirmed resource reserved again = %#v, want conflict", result)
	}
}

// The at-least-once law made exactly-once: the kernel journals an intent
// before the effect and re-drives it after a crash under the same idempotency
// key, so the same reserve dispatched twice under one key must hold once and
// answer byte-identically — not conflict with its own first execution.
func TestHoldReserveExactlyOnceUnderIdempotencyKey(t *testing.T) {
	minted := 0
	h := &hold.Handler{Name: "inv", NewID: sequenceIDs(&minted)}
	intent := sys.WithIdempotencyKey(context.Background(), "proc-1/3/sha256:reserve")

	first := dispatchCtx(t, intent, h, "inv.reserve", `{"resource":"seat-1A"}`)
	if first.Status() != sys.StatusResult {
		t.Fatalf("first reserve = %#v", first)
	}
	redriven := dispatchCtx(t, intent, h, "inv.reserve", `{"resource":"seat-1A"}`)
	if redriven.Status() != sys.StatusResult {
		t.Fatalf("re-driven reserve = %#v, want the recorded result, not a conflict", redriven)
	}
	if string(redriven.Result()) != string(first.Result()) {
		t.Fatalf("re-driven result diverged: %s vs %s", redriven.Result(), first.Result())
	}
	if minted != 1 {
		t.Fatalf("minted %d holds, want 1 (a deduped reserve must not hold twice)", minted)
	}

	// The memory is keyed by intent, not by call shape: a distinct intent with
	// the same arguments executes for real — and now genuinely conflicts.
	other := sys.WithIdempotencyKey(context.Background(), "proc-1/9/sha256:reserve")
	if result := dispatchCtx(t, other, h, "inv.reserve", `{"resource":"seat-1A"}`); result.Errno() != sys.ErrnoConflict {
		t.Fatalf("fresh intent = %#v, want a real conflict", result)
	}
	// A conflict is a non-effect and records nothing: once the hold is
	// released, the same re-driven intent succeeds for real.
	var held hold.ReserveResponse
	if err := json.Unmarshal(first.Result(), &held); err != nil {
		t.Fatalf("decode reserve: %v", err)
	}
	dispatch(t, h, "inv.release", `{"hold_id":"`+held.HoldID+`"}`)
	if result := dispatchCtx(t, other, h, "inv.reserve", `{"resource":"seat-1A"}`); result.Status() != sys.StatusResult {
		t.Fatalf("retried intent after release = %#v, want success", result)
	}
}

// Requests fail closed: malformed JSON, missing fields, and out-of-bounds
// TTLs are invalid_args; unknown operations are not_found.
func TestHoldValidatesArguments(t *testing.T) {
	h := &hold.Handler{Name: "inv"}

	for _, operation := range []string{"inv.reserve", "inv.confirm", "inv.release"} {
		if result := dispatch(t, h, operation, `{`); result.Errno() != sys.ErrnoInvalidArgs {
			t.Fatalf("malformed %s = %#v, want invalid_args", operation, result)
		}
	}
	for _, args := range []string{`{}`, `{"resource":""}`, `{"resource":"r","ttl_seconds":-5}`, `{"resource":"r","ttl_seconds":86401}`} {
		if result := dispatch(t, h, "inv.reserve", args); result.Errno() != sys.ErrnoInvalidArgs {
			t.Fatalf("reserve %s = %#v, want invalid_args", args, result)
		}
	}
	// The ceiling itself is allowed.
	reserved(t, dispatch(t, h, "inv.reserve", `{"resource":"r","ttl_seconds":86400}`))

	if result := dispatch(t, h, "inv.confirm", `{}`); result.Errno() != sys.ErrnoInvalidArgs {
		t.Fatalf("confirm without hold_id = %#v, want invalid_args", result)
	}
	if result := dispatch(t, h, "inv.release", `{}`); result.Errno() != sys.ErrnoInvalidArgs {
		t.Fatalf("release without hold_id = %#v, want invalid_args", result)
	}
	if result := dispatch(t, h, "inv.expropriate", `{}`); result.Errno() != sys.ErrnoNotFound {
		t.Fatalf("unknown operation = %#v, want not_found", result)
	}
}
