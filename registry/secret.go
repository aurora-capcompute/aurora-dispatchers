package registry

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// SecretResolver resolves a manifest secret reference (a logical name) to its
// value, host-side. The value never enters the manifest, the journal, or the
// guest — only the reference name is persisted. The assembly supplies the
// implementation (env vars, a file, or a real secret manager). A nil resolver
// means no references may be used: a grant that references one fails closed.
type SecretResolver interface {
	// Resolve returns the secret's value and whether the name is known.
	Resolve(name string) (value string, ok bool)
}

// Secret is a credential-bearing manifest field. It is only ever a reference
// {"secret":"NAME"}: the host resolves the value where the driver needs it (in
// aurora-dist, from the AURORA_SECRET_<NAME> environment variable), so the value
// never enters the manifest, the journal, or the guest. A literal value is
// refused when the manifest is decoded.
type Secret struct {
	ref string
}

// SecretRef is a reference resolved host-side from the named secret.
func SecretRef(name string) Secret { return Secret{ref: strings.TrimSpace(name)} }

// IsZero reports whether no credential was supplied.
func (s Secret) IsZero() bool { return s.ref == "" }

// Ref returns the reference name (empty for a zero secret).
func (s Secret) Ref() string { return s.ref }

func (s *Secret) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*s = Secret{}
		return nil
	}
	if data[0] == '"' {
		return fmt.Errorf(`a secret is a reference {"secret":"NAME"}, never an inline value; provide the value to the host (aurora-dist: AURORA_SECRET_NAME)`)
	}
	var ref struct {
		Secret string `json:"secret"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ref); err != nil {
		return fmt.Errorf(`secret must be {"secret":"NAME"}: %w`, err)
	}
	name := strings.TrimSpace(ref.Secret)
	if name == "" {
		return fmt.Errorf("secret reference name is empty")
	}
	*s = Secret{ref: name}
	return nil
}

func (s Secret) MarshalJSON() ([]byte, error) {
	if s.ref == "" {
		return []byte("null"), nil
	}
	return json.Marshal(map[string]string{"secret": s.ref})
}

// Resolve looks the reference up through the resolver; a zero secret resolves
// to "" (no credential). A reference with no resolver configured, or an unknown
// name, is a fail-closed error — the driver refuses to build rather than run
// without the credential (so a missing secret fails at activation, and is
// recorded there, never silently at dispatch).
func (s Secret) Resolve(secrets SecretResolver) (string, error) {
	if s.ref == "" {
		return "", nil
	}
	if secrets == nil {
		return "", fmt.Errorf("secret %q referenced but no secret resolver is configured", s.ref)
	}
	value, ok := secrets.Resolve(s.ref)
	if !ok {
		return "", fmt.Errorf("secret %q is not available", s.ref)
	}
	return value, nil
}

// CredentialFingerprint is a non-reversible, correlatable id for an injected
// credential — HMAC-SHA256(auditKey, value), truncated — so the audit trail can
// record which credential was used, and detect rotation, without ever recording
// the value. The key keeps a low-entropy secret from being brute-forced out of
// its fingerprint; an empty key still yields a stable (unkeyed) fingerprint.
func CredentialFingerprint(auditKey []byte, value string) string {
	mac := hmac.New(sha256.New, auditKey)
	_, _ = mac.Write([]byte("aurora/credential\x00"))
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))[:12]
}
