package resolution

import (
	"context"
	"encoding/json"
)

type Decision string

const (
	Approved  Decision = "approved"
	Completed Decision = "completed"
	Failed    Decision = "failed"
	Denied    Decision = "denied"
	Cancelled Decision = "cancelled"
)

type Resolution struct {
	Decision Decision        `json:"decision"`
	Data     json.RawMessage `json:"data,omitempty"`
	Actor    string          `json:"actor,omitempty"`
	Reason   string          `json:"reason,omitempty"`
}

type contextKey struct{}

func WithContext(ctx context.Context, value Resolution) context.Context {
	return context.WithValue(ctx, contextKey{}, value)
}

func FromContext(ctx context.Context) (Resolution, bool) {
	value, ok := ctx.Value(contextKey{}).(Resolution)
	return value, ok
}
