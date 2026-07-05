// Package hold provides the reference Try-Confirm/Cancel (TCC) reservation
// driver — saga isolation for critical sections (capcompute docs/ROADMAP.md
// #19).
//
// Sagas have no isolation (García-Molina & Salem, "Sagas", SIGMOD '87): while
// a multi-step section is in flight its partial effects are visible as
// ordinary state, and the classic countermeasure is a semantic lock — a
// pending reservation instead of a dirty write. The runtime already owns the
// Cancel leg: a guest registers an effect's undo with sys.compensate, and
// sys.abort runs the registered undos newest-first. This driver adds the
// Try-Confirm leg (Pardon & Pautasso, "Atomic Distributed Transactions: a
// RESTful Design", WWW '14): <name>.reserve places an explicitly PENDING,
// self-expiring hold on a resource (the Try), <name>.confirm makes it
// permanent (the Confirm — call it before sys.commit closes the section), and
// <name>.release cancels it (the Cancel — the natural sys.compensate target).
// Intermediate state becomes a first-class hold other actors can observe and
// respect, never an ambiguous half-write.
//
// The hold state machine:
//
//	(free) --reserve--> PENDING --confirm--> CONFIRMED   terminal: kept
//	                    PENDING --release--> (free)      the Cancel leg
//	                    PENDING --deadline--> EXPIRED    lazy: purged when its
//	                                                     id or resource is next
//	                                                     touched; frees the
//	                                                     resource
//
// A resource with a live hold (pending and unexpired, or confirmed) cannot be
// reserved again — errno conflict. Confirming past the deadline fails with
// errno expired; confirming a confirmed hold succeeds (idempotent). Releasing
// an unknown, expired, or already-released hold succeeds — an undo must never
// fail for being already undone — while a confirmed hold refuses release with
// errno conflict: confirmed means kept.
//
// Exactly-once: the kernel journals an intent before a syscall executes and
// re-drives it after a crash — at-least-once — under a stable idempotency key
// (Helland, "Life beyond Distributed Transactions"). reserve is the effect,
// so it keeps an activity memory: a re-seen key replays the recorded response
// byte-identically instead of minting a second hold (or conflicting with its
// own first try). confirm and release are naturally idempotent and need no
// record. hold_id comes from an injectable id source (crypto/rand hex by
// default): driver-side effect values are journaled and replayed verbatim, so
// nondeterminism here is fine.
//
// This is the REFERENCE shape: a process-local, in-memory hold table that
// demonstrates the protocol. A production resource owner keeps holds durably
// on its own side — the reservation lives next to the resource, like a seat
// map in the airline's database — exposing these same three operations.
package hold

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aurora-capcompute/capcompute/sys"
)

// DefaultTTL is the pending window when neither the grant's settings nor the
// call name one. Short by design: a hold is a semantic lock, and an abandoned
// lock must lapse on its own.
const DefaultTTL = 5 * time.Minute

// MaxTTL caps every pending window — the settings default and the per-call
// override alike. A hold is a bounded reservation, not a permanent lease;
// state that must outlive it belongs in durable storage.
const MaxTTL = 24 * time.Hour

// ReserveRequest places a hold on one resource. Resource is a caller-chosen
// identifier (a seat, an order id, a budget line); TTLSeconds optionally
// overrides the grant's default pending window, bounded by MaxTTL.
type ReserveRequest struct {
	Resource   string `json:"resource"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
}

// ReserveResponse identifies the new pending hold. ExpiresAtMS is the instant
// the hold lapses unless confirmed first.
type ReserveResponse struct {
	HoldID      string `json:"hold_id"`
	Resource    string `json:"resource"`
	ExpiresAtMS int64  `json:"expires_at_ms"`
}

type ConfirmRequest struct {
	HoldID string `json:"hold_id"`
}

type ConfirmResponse struct {
	Confirmed bool `json:"confirmed"`
}

type ReleaseRequest struct {
	HoldID string `json:"hold_id"`
}

type ReleaseResponse struct {
	Released bool `json:"released"`
}

// record is one hold: PENDING until confirmed, released, or expired. A
// confirmed record is terminal and ignores its deadline — the deadline bounds
// only the pending window; confirmed means kept.
type record struct {
	resource  string
	deadline  time.Time
	confirmed bool
}

// Handler serves one core.hold grant. It satisfies builtin.Handler and
// publishes <Name>.reserve, <Name>.confirm, and <Name>.release.
//
// State is in-memory, per handler instance — the reference shape: a
// process-local hold table demonstrating the protocol. A production resource
// owner keeps holds durably on its own side. Methods are on *Handler; share
// one instance, never copy it.
type Handler struct {
	// Name is the tool's local manifest name; operations are <Name>.reserve etc.
	Name string
	// DefaultTTL is the pending window when a reserve names none. Zero uses
	// the package DefaultTTL.
	DefaultTTL time.Duration
	// Now is the clock, injectable for tests and simulation. Nil uses
	// time.Now. Expiry is judged lazily against it on access — there is no
	// background sweeper.
	Now func() time.Time
	// NewID mints hold ids. Nil uses 16 bytes of crypto/rand as hex. Effect
	// values are journaled and replayed verbatim, so nondeterminism is fine.
	NewID func() (string, error)

	// The hold table, guarded by mu: holds by id, plus an index mapping each
	// resource to its one live hold. Expired pending holds are purged lazily
	// when their id or resource is next touched. reserved is the activity
	// memory for reserve (idempotency key → recorded response bytes); like
	// the table itself it is process-local and grows with use, which the
	// reference role affords.
	mu        sync.Mutex
	holds     map[string]*record
	resources map[string]string
	reserved  map[string]json.RawMessage
}

// Handles reports whether the handler owns the given operation name.
func (h *Handler) Handles(name string) bool {
	return name == h.Name+".reserve" || name == h.Name+".confirm" || name == h.Name+".release"
}

// DispatchCall routes one hold operation. Only reserve consults the dispatch
// context (for its idempotency key); no operation yields — the hold itself is
// the pending state, so nothing here waits on a human.
func (h *Handler) DispatchCall(ctx context.Context, call sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	switch strings.TrimPrefix(call.Name, h.Name+".") {
	case "reserve":
		return h.reserve(ctx, call)
	case "confirm":
		return h.confirm(call)
	case "release":
		return h.release(call)
	default:
		return sys.FailCode(sys.ErrnoNotFound, "unknown hold operation: "+call.Name), nil
	}
}

// reserve is the Try leg: it places a pending hold on a free resource. A live
// hold (pending and unexpired, or confirmed) blocks the resource — errno
// conflict; an expired pending hold is purged on the way through.
func (h *Handler) reserve(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error) {
	var request ReserveRequest
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", call.Name, err)), nil
	}
	if request.Resource == "" {
		return sys.FailCode(sys.ErrnoInvalidArgs, "resource is required"), nil
	}
	if request.TTLSeconds < 0 {
		return sys.FailCode(sys.ErrnoInvalidArgs, "ttl_seconds must be positive"), nil
	}
	ttl := h.DefaultTTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if request.TTLSeconds > 0 {
		requested := time.Duration(request.TTLSeconds) * time.Second
		if requested > MaxTTL {
			return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("ttl_seconds must be at most %d", int64(MaxTTL/time.Second))), nil
		}
		ttl = requested
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	// Exactly-once across the intent→completion crash window: the kernel
	// journals an intent before the effect and re-drives it after a crash
	// under the same idempotency key. A recorded key means this reserve
	// already executed — replay its response byte-identically instead of
	// minting a second hold (or conflicting with our own first try). The key
	// pins the call-hash, so a re-seen key carries these same arguments.
	idem, _ := sys.IdempotencyKey(ctx)
	if idem != "" {
		if recorded, done := h.reserved[idem]; done {
			return sys.Result(recorded), nil
		}
	}
	now := h.clock()
	if id, ok := h.resources[request.Resource]; ok {
		held := h.holds[id]
		if held.confirmed {
			return sys.FailCode(sys.ErrnoConflict, fmt.Sprintf("resource %q is kept by confirmed hold %q", request.Resource, id)), nil
		}
		if now.Before(held.deadline) {
			return sys.FailCode(sys.ErrnoConflict, fmt.Sprintf("resource %q is held by pending hold %q until %d ms; release it or wait for expiry", request.Resource, id, held.deadline.UnixMilli())), nil
		}
		// The pending hold lapsed: purge it lazily — the resource is free again.
		h.purge(id, held)
	}
	id, err := h.mint()
	if err != nil {
		return sys.FailCode(sys.ErrnoInternal, fmt.Sprintf("mint hold id: %v", err)), nil
	}
	deadline := now.Add(ttl)
	response, err := json.Marshal(ReserveResponse{HoldID: id, Resource: request.Resource, ExpiresAtMS: deadline.UnixMilli()})
	if err != nil {
		return sys.SyscallResult{}, err
	}
	if h.holds == nil {
		h.holds = make(map[string]*record)
		h.resources = make(map[string]string)
	}
	h.holds[id] = &record{resource: request.Resource, deadline: deadline}
	h.resources[request.Resource] = id
	if idem != "" {
		if h.reserved == nil {
			h.reserved = make(map[string]json.RawMessage)
		}
		// Recorded under the same mutex hold as the write: atomic. A conflict
		// above recorded nothing — a non-effect is safe to re-evaluate.
		h.reserved[idem] = response
	}
	return sys.Result(response), nil
}

// confirm is the Confirm leg: it makes a pending hold permanent. Idempotent
// for a confirmed hold; errno expired past the deadline (the lapsed hold is
// purged and the resource is free again); errno not_found for ids that never
// existed or are already gone.
func (h *Handler) confirm(call sys.Syscall) (sys.SyscallResult, error) {
	var request ConfirmRequest
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", call.Name, err)), nil
	}
	if request.HoldID == "" {
		return sys.FailCode(sys.ErrnoInvalidArgs, "hold_id is required"), nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	held, ok := h.holds[request.HoldID]
	if !ok {
		return sys.FailCode(sys.ErrnoNotFound, fmt.Sprintf("hold %q does not exist (never reserved, released, or expired and purged)", request.HoldID)), nil
	}
	if held.confirmed {
		// Idempotent: the confirmation already happened; report it again.
		return marshalResult(ConfirmResponse{Confirmed: true})
	}
	if !h.clock().Before(held.deadline) {
		// Lazy expiry observed at the deadline: the Try is void. Purge the
		// lapsed hold — the resource is free again.
		h.purge(request.HoldID, held)
		return sys.FailCode(sys.ErrnoExpired, fmt.Sprintf("hold %q expired at %d ms; the resource is free again — re-reserve and retry", request.HoldID, held.deadline.UnixMilli())), nil
	}
	held.confirmed = true
	return marshalResult(ConfirmResponse{Confirmed: true})
}

// release is the Cancel leg and the natural sys.compensate target. It is
// idempotent the way an undo must be: releasing an unknown, expired, or
// already-released hold succeeds — never failing for being already undone. A
// confirmed hold refuses release with errno conflict: confirmed means kept.
func (h *Handler) release(call sys.Syscall) (sys.SyscallResult, error) {
	var request ReleaseRequest
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", call.Name, err)), nil
	}
	if request.HoldID == "" {
		return sys.FailCode(sys.ErrnoInvalidArgs, "hold_id is required"), nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	held, ok := h.holds[request.HoldID]
	if !ok {
		// Unknown, already released, or expired and purged: the undo's work
		// is already done.
		return marshalResult(ReleaseResponse{Released: true})
	}
	if held.confirmed {
		return sys.FailCode(sys.ErrnoConflict, fmt.Sprintf("hold %q is confirmed and cannot be released — confirmed means kept", request.HoldID)), nil
	}
	// Pending or lapsed alike: drop the hold and free the resource.
	h.purge(request.HoldID, held)
	return marshalResult(ReleaseResponse{Released: true})
}

// purge removes a hold and its resource index entry. Callers hold mu.
func (h *Handler) purge(id string, held *record) {
	delete(h.holds, id)
	if h.resources[held.resource] == id {
		delete(h.resources, held.resource)
	}
}

func (h *Handler) clock() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Handler) mint() (string, error) {
	if h.NewID != nil {
		return h.NewID()
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func marshalResult(value any) (sys.SyscallResult, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return sys.SyscallResult{}, err
	}
	return sys.Result(raw), nil
}
