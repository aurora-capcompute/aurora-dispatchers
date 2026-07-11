package k8s

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The projected service-account token rotates; fileToken must serve a cached
// value within the read interval and pick up a rotated value past it.
func TestFileTokenCachesAndRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	writeFile(t, path, "tok-1\n")

	now := time.Unix(1_000_000, 0)
	ft := newFileToken(path)
	ft.now = func() time.Time { return now }

	if got, err := ft.token(); err != nil || got != "tok-1" {
		t.Fatalf("first read = %q/%v, want tok-1 (trimmed)", got, err)
	}
	// Rotate on disk; within the interval the cached value still serves.
	writeFile(t, path, "tok-2")
	now = now.Add(tokenReadInterval / 2)
	if got, _ := ft.token(); got != "tok-1" {
		t.Fatalf("within-interval read = %q, want cached tok-1", got)
	}
	// Past the interval the rotated token is picked up.
	now = now.Add(tokenReadInterval)
	if got, _ := ft.token(); got != "tok-2" {
		t.Fatalf("post-interval read = %q, want rotated tok-2", got)
	}
}

// A transient read failure (or a momentarily-empty file) must fall back to the
// last good token rather than failing the request outright.
func TestFileTokenFallsBackToLastGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	writeFile(t, path, "tok-1")

	now := time.Unix(2_000_000, 0)
	ft := newFileToken(path)
	ft.now = func() time.Time { return now }
	if _, err := ft.token(); err != nil {
		t.Fatalf("seed read: %v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	now = now.Add(2 * tokenReadInterval)
	if got, err := ft.token(); err != nil || got != "tok-1" {
		t.Fatalf("missing-file read = %q/%v, want last-good tok-1", got, err)
	}

	writeFile(t, path, "   ") // whitespace-only trims to empty
	now = now.Add(2 * tokenReadInterval)
	if got, _ := ft.token(); got != "tok-1" {
		t.Fatalf("empty-file read = %q, want last-good tok-1", got)
	}
}

// With no cached value, a missing token file is a hard error (fail closed).
func TestFileTokenErrorsWithoutCache(t *testing.T) {
	ft := newFileToken(filepath.Join(t.TempDir(), "absent"))
	if _, err := ft.token(); err == nil {
		t.Fatal("missing token file with no cached value must error")
	}
}

// A malformed cluster CA must fail NewClient closed — never fall through to
// skipping verification.
func TestNewClientRejectsInvalidCA(t *testing.T) {
	access := Access{endpoint: "https://api.test", caPEM: []byte("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----"), tokens: staticToken("t")}
	if _, err := NewClient(access, Options{}); err == nil {
		t.Fatal("NewClient accepted an invalid CA PEM")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
