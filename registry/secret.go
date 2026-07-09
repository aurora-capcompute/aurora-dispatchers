package registry

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
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

// Secret is a credential-bearing manifest field: either a literal value
// (soft-deprecated — a literal sprawls into the persisted manifest and the
// journal) or a reference {"secret":"NAME"} resolved host-side so the value
// never touches the manifest, journal, or guest. It round-trips through
// Normalize preserving the reference form.
type Secret struct {
	literal string
	ref     string
}

// LiteralSecret is a plain in-manifest value (the soft-deprecated form).
func LiteralSecret(v string) Secret { return Secret{literal: v} }

// SecretRef is a reference resolved host-side from the named secret.
func SecretRef(name string) Secret { return Secret{ref: strings.TrimSpace(name)} }

// IsZero reports whether no credential was supplied.
func (s Secret) IsZero() bool { return s.literal == "" && s.ref == "" }

// Ref returns the reference name (empty for a literal or zero secret).
func (s Secret) Ref() string { return s.ref }

func (s *Secret) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		*s = Secret{}
		return nil
	}
	if trimmed[0] == '"' {
		var literal string
		if err := json.Unmarshal(trimmed, &literal); err != nil {
			return err
		}
		*s = Secret{literal: literal}
		return nil
	}
	var ref struct {
		Secret string `json:"secret"`
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ref); err != nil {
		return fmt.Errorf(`secret must be a string or {"secret":"NAME"}: %w`, err)
	}
	name := strings.TrimSpace(ref.Secret)
	if name == "" {
		return fmt.Errorf("secret reference name is empty")
	}
	*s = Secret{ref: name}
	return nil
}

func (s Secret) MarshalJSON() ([]byte, error) {
	if s.ref != "" {
		return json.Marshal(map[string]string{"secret": s.ref})
	}
	return json.Marshal(s.literal)
}

// Resolve returns the secret's value: a literal verbatim, or a reference looked
// up through the resolver. A reference with no resolver configured, or an
// unknown name, is a fail-closed error — the driver refuses to build rather than
// run without the credential (so a missing secret fails at activation, and is
// recorded there, never silently at dispatch).
func (s Secret) Resolve(secrets SecretResolver) (string, error) {
	if s.ref == "" {
		return s.literal, nil
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

// isLoopbackHost reports whether host (optionally host:port) is loopback, where
// plain HTTP carries no wire to sniff — the sole exception to the TLS
// requirement for credential injection.
func isLoopbackHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
