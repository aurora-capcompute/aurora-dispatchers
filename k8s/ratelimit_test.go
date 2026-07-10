package k8s

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakeClock is a virtual clock whose sleep advances time instantly, so the rate
// limiter's pacing is tested deterministically without real waits.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (c *fakeClock) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.advance(d)
	return nil
}

func newTestLimiter(perSecond float64, burst int) (*rateLimiter, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	l := newRateLimiter(perSecond, burst)
	l.now = clk.now
	l.sleep = clk.sleep
	l.last = clk.now()
	return l, clk
}

// The burst is spendable instantly; past it, the limiter paces to the
// configured requests-per-second ceiling.
func TestRateLimiterCapsSteadyState(t *testing.T) {
	l, clk := newTestLimiter(10, 5) // 10 req/s, burst 5
	ctx := context.Background()
	start := clk.now()

	// Burst of 5 spends no virtual time.
	for i := 0; i < 5; i++ {
		if err := l.wait(ctx); err != nil {
			t.Fatalf("burst wait %d: %v", i, err)
		}
	}
	if elapsed := clk.now().Sub(start); elapsed != 0 {
		t.Fatalf("burst consumed %v of virtual time, want 0", elapsed)
	}

	// The next 20 are paced at 10/s, so they take ~2s of virtual time.
	for i := 0; i < 20; i++ {
		if err := l.wait(ctx); err != nil {
			t.Fatalf("paced wait %d: %v", i, err)
		}
	}
	elapsed := clk.now().Sub(start)
	// 20 requests / 10 per second = 2s, allowing a small rounding margin for the
	// 1ms minimum sleep.
	if elapsed < 1900*time.Millisecond || elapsed > 2100*time.Millisecond {
		t.Fatalf("20 paced requests took %v, want ~2s", elapsed)
	}
}

// A single request against a fresh limiter is admitted immediately (a token is
// waiting), so a program's first read is not delayed.
func TestRateLimiterFirstRequestImmediate(t *testing.T) {
	l, clk := newTestLimiter(1, 1)
	start := clk.now()
	if err := l.wait(context.Background()); err != nil {
		t.Fatalf("wait: %v", err)
	}
	if elapsed := clk.now().Sub(start); elapsed != 0 {
		t.Fatalf("first request waited %v, want 0", elapsed)
	}
}

// A server-requested cooldown parks the whole grant: the next request cannot go
// until the cooldown elapses, even with tokens in the bucket.
func TestRateLimiterHonorsBackoff(t *testing.T) {
	l, clk := newTestLimiter(100, 10) // plenty of tokens
	start := clk.now()
	l.backoff(3 * time.Second)
	if err := l.wait(context.Background()); err != nil {
		t.Fatalf("wait: %v", err)
	}
	if elapsed := clk.now().Sub(start); elapsed < 3*time.Second {
		t.Fatalf("request went after %v, want to wait out the 3s cooldown", elapsed)
	}
}

// A longer pending cooldown is never shortened by a later, smaller backoff.
func TestRateLimiterBackoffTakesTheLonger(t *testing.T) {
	l, clk := newTestLimiter(100, 10)
	start := clk.now()
	l.backoff(5 * time.Second)
	l.backoff(1 * time.Second) // must not shorten the standing 5s
	if err := l.wait(context.Background()); err != nil {
		t.Fatalf("wait: %v", err)
	}
	if elapsed := clk.now().Sub(start); elapsed < 5*time.Second {
		t.Fatalf("request went after %v, want the longer 5s cooldown", elapsed)
	}
}

// A cancelled context aborts the wait and spends no token, so a cancellation can
// never push the grant past its ceiling.
func TestRateLimiterRespectsContextCancellation(t *testing.T) {
	l, _ := newTestLimiter(1, 1)
	// Drain the one burst token so the next wait would have to sleep.
	if err := l.wait(context.Background()); err != nil {
		t.Fatalf("prime: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.wait(ctx); err == nil {
		t.Fatal("wait on a cancelled context returned nil, want the context error")
	}
}

// A nil limiter admits immediately — the no-rate-limit configuration.
func TestNilRateLimiterAdmits(t *testing.T) {
	var l *rateLimiter
	if err := l.wait(context.Background()); err != nil {
		t.Fatalf("nil limiter wait: %v", err)
	}
	l.backoff(time.Second) // must be a no-op, not a panic
}
