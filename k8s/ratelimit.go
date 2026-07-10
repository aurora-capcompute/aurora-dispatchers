package k8s

import (
	"context"
	"sync"
	"time"
)

// rateLimiter is a token bucket that paces one grant's requests to the
// Kubernetes API. It exists so a guest cannot burst past a fixed
// requests-per-second ceiling and so the driver honors server backpressure: a
// 429/503 Retry-After sets a cooldown the whole grant waits out before its next
// request. One limiter is shared by every call of a grant, so a run that fires
// many k8s reads in a row is spaced out rather than allowed to hammer the API.
//
// now and sleep are injected so tests can drive the limiter on a virtual clock
// without real waits; production uses the wall clock and a context-aware timer.
type rateLimiter struct {
	mu       sync.Mutex
	tokens   float64   // whole requests available, refilling fractionally over time
	burst    float64   // bucket capacity: the most requests spendable at once
	perSec   float64   // refill rate: the steady-state requests/second ceiling
	last     time.Time // when tokens were last refilled
	cooldown time.Time // server-requested floor: no request may go before this

	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

// newRateLimiter builds a limiter admitting at most perSecond requests per
// second in steady state, with a bucket of burst tokens for short spikes. Both
// are floored to sane minimums so a misconfigured grant still rate-limits rather
// than dividing by zero or never admitting.
func newRateLimiter(perSecond float64, burst int) *rateLimiter {
	if perSecond <= 0 {
		perSecond = 1
	}
	if burst < 1 {
		burst = 1
	}
	l := &rateLimiter{
		tokens: float64(burst),
		burst:  float64(burst),
		perSec: perSecond,
		now:    time.Now,
		sleep:  sleepContext,
	}
	l.last = l.now()
	return l
}

// wait blocks until a token is available (and any server cooldown has elapsed),
// then spends it. It returns the context's error if the wait is cancelled — a
// cancelled wait spends nothing, so the ceiling is never exceeded by a
// cancellation. A nil limiter admits immediately (no limiting configured).
func (l *rateLimiter) wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		l.mu.Lock()
		now := l.now()
		// A server-requested cooldown outranks token availability: wait it out
		// first, then re-evaluate.
		if pause := l.cooldown.Sub(now); pause > 0 {
			l.mu.Unlock()
			if err := l.sleep(ctx, pause); err != nil {
				return err
			}
			continue
		}
		// Refill for the elapsed time since the last spend, capped at the burst so
		// idle time cannot bank unlimited requests.
		if now.After(l.last) {
			l.tokens += now.Sub(l.last).Seconds() * l.perSec
			if l.tokens > l.burst {
				l.tokens = l.burst
			}
			l.last = now
		}
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		// Not enough yet: sleep exactly long enough to refill the deficit, then
		// loop to spend it. Round up so the sleep never leaves us a hair short.
		pause := time.Duration((1 - l.tokens) / l.perSec * float64(time.Second))
		if pause < time.Millisecond {
			pause = time.Millisecond
		}
		l.mu.Unlock()
		if err := l.sleep(ctx, pause); err != nil {
			return err
		}
	}
}

// backoff records a server-requested cooldown: no request may leave this grant
// for the next d. Called when the API answers 429/503 with a Retry-After, so the
// whole grant — not just the call that saw the push-back — slows down. A longer
// pending cooldown is never shortened.
func (l *rateLimiter) backoff(d time.Duration) {
	if l == nil || d <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	until := l.now().Add(d)
	if until.After(l.cooldown) {
		l.cooldown = until
	}
}

// sleepContext waits for d or until ctx is done, whichever comes first — the
// production sleep. A non-positive duration returns immediately.
func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
