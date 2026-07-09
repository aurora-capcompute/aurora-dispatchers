package registry_test

import (
	"encoding/json"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/registry"
)

// mapResolver is a test SecretResolver backed by a map.
type mapResolver map[string]string

func (m mapResolver) Resolve(name string) (string, bool) { v, ok := m[name]; return v, ok }

func TestSecretUnmarshalMarshal(t *testing.T) {
	var literal registry.Secret
	if err := json.Unmarshal([]byte(`"sk-123"`), &literal); err != nil {
		t.Fatalf("literal: %v", err)
	}
	if literal.Ref() != "" {
		t.Fatalf("a plain string parsed as a reference")
	}

	var ref registry.Secret
	if err := json.Unmarshal([]byte(`{"secret":"ONYX_TOKEN"}`), &ref); err != nil {
		t.Fatalf("ref: %v", err)
	}
	if ref.Ref() != "ONYX_TOKEN" {
		t.Fatalf("ref = %q", ref.Ref())
	}
	// A reference round-trips as a reference — never a resolved value.
	out, err := json.Marshal(ref)
	if err != nil || string(out) != `{"secret":"ONYX_TOKEN"}` {
		t.Fatalf("marshal = %s (err %v)", out, err)
	}

	for name, bad := range map[string]string{
		"empty name":    `{"secret":""}`,
		"unknown field": `{"secret":"X","extra":1}`,
	} {
		var s registry.Secret
		if err := json.Unmarshal([]byte(bad), &s); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestSecretResolveFailsClosed(t *testing.T) {
	res := mapResolver{"ONYX_TOKEN": "tok-abc"}

	if v, err := registry.LiteralSecret("lit").Resolve(nil); err != nil || v != "lit" {
		t.Fatalf("literal resolve = %q, %v", v, err)
	}
	if v, err := registry.SecretRef("ONYX_TOKEN").Resolve(res); err != nil || v != "tok-abc" {
		t.Fatalf("ref resolve = %q, %v", v, err)
	}
	if _, err := registry.SecretRef("ONYX_TOKEN").Resolve(nil); err == nil {
		t.Fatal("a reference resolved with no resolver configured")
	}
	if _, err := registry.SecretRef("MISSING").Resolve(res); err == nil {
		t.Fatal("an unknown reference resolved")
	}
}

func TestCredentialFingerprintStableAndKeyed(t *testing.T) {
	fp := registry.CredentialFingerprint([]byte("k"), "tok-abc")
	if fp != registry.CredentialFingerprint([]byte("k"), "tok-abc") {
		t.Fatal("fingerprint is not stable")
	}
	if fp == registry.CredentialFingerprint([]byte("k2"), "tok-abc") {
		t.Fatal("fingerprint ignores the key")
	}
	if fp == registry.CredentialFingerprint([]byte("k"), "tok-xyz") {
		t.Fatal("fingerprint ignores the value")
	}
	if len(fp) != 12 {
		t.Fatalf("fingerprint length = %d, want 12", len(fp))
	}
}
