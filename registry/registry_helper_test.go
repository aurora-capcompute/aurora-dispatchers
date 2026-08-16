package registry_test

import (
	"context"
	"encoding/json"

	"github.com/aurora-capcompute/aurora-dispatchers/registry"
)

// registryValidate is the door check one registration at a time: it builds what
// the spawn would build and throws it away, so a test asserting a refusal is
// asserting exactly what CreateProcess asserts.
func registryValidate(r registry.Registration, syscall string, config json.RawMessage) (json.RawMessage, error) {
	// A permissive resolver: validation builds what the spawn would build, so a
	// grant referencing a host-held secret needs one. Tests about refusals still
	// refuse on their own grounds; this only keeps a missing secret from standing
	// in for the failure they mean to assert.
	services := registry.Services{Secrets: anySecret{}}
	err := registry.New(r).ValidateConfig(context.Background(), syscall, config, services)
	return config, err
}

type anySecret struct{}

func (anySecret) Resolve(name string) (string, bool) { return "resolved-" + name, true }
