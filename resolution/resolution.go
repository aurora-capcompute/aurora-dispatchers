// Package resolution re-exports the resolution vocabulary from capcompute/resolution.
// The actual implementation lives in capcompute so that aurora-capcompute can import
// it without depending on aurora-dispatchers; all existing callers of this package
// continue to work without changes.
package resolution

import (
	"context"

	capresolution "github.com/aurora-capcompute/capcompute/resolution"
)

type Decision = capresolution.Decision

const (
	Approved  = capresolution.Approved
	Completed = capresolution.Completed
	Failed    = capresolution.Failed
	Denied    = capresolution.Denied
	Cancelled = capresolution.Cancelled
)

type Resolution = capresolution.Resolution

func WithContext(ctx context.Context, value Resolution) context.Context {
	return capresolution.WithContext(ctx, value)
}

func FromContext(ctx context.Context) (Resolution, bool) {
	return capresolution.FromContext(ctx)
}
