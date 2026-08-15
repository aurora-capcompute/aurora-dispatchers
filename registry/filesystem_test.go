package registry_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-dispatchers/filesystem"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
)

func filesystemRegistry() *registry.Registry {
	return registry.New(registry.FilesystemRegistration{})
}

func buildFilesystemTable(t *testing.T, config string) *capability.Table {
	t.Helper()
	built, err := filesystemRegistry().Build(context.Background(),
		[]registry.Entry{{Syscall: "core.filesystem", Config: json.RawMessage(config)}},
		registry.Services{},
	)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(built.Descriptors()) != 1 || built.Descriptors()[0].Name != filesystem.Capability {
		t.Fatalf("capabilities = %+v, want one named %s", built.Descriptors(), filesystem.Capability)
	}
	if !strings.Contains(string(built.Descriptors()[0].InputSchema), `"oneOf"`) {
		t.Fatalf("input schema is not a oneOf ADT: %s", built.Descriptors()[0].InputSchema)
	}
	if len(built.Entries()) == 0 {
		t.Fatalf("no operations indexed: %+v", built.Descriptors())
	}
	return built
}

func buildFilesystem(t *testing.T, config string) capability.Handler {
	return buildFilesystemTable(t, config).Entries()[0].Handler
}

func rootConfig(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	config := `{"capabilities":[{"operation":"read"}],"roots":["` + dir + `"]`
	if extra != "" {
		config += "," + extra
	}
	return config + "}"
}

// Operations are cases of one capability, so they are indexed under the
// capability's own name — never as capability names of their own.
func TestFilesystemPublishesOneCapability(t *testing.T) {
	table := buildFilesystemTable(t, rootConfig(t, ""))
	if got := table.Operations("core.filesystem"); len(got) != 1 || got[0] != "read" {
		t.Fatalf("operations = %v, want [read] under core.filesystem", got)
	}
	if len(table.Operations("filesystem.read")) != 0 {
		t.Fatal("operations are ADT cases, not separate capability names")
	}
	if caps := table.Descriptors(); len(caps) != 1 || caps[0].Name != "core.filesystem" {
		t.Fatalf("capabilities = %+v, want one named core.filesystem", caps)
	}
}

func TestFilesystemMatches(t *testing.T) {
	if !(registry.FilesystemRegistration{}).Matches("core.filesystem") {
		t.Fatal("should match core.filesystem")
	}
	if (registry.FilesystemRegistration{}).Matches("core.scratch") {
		t.Fatal("should not match core.memory")
	}
}

func TestFilesystemNormalizeAbsolutizesRoots(t *testing.T) {
	dir := t.TempDir()
	// A relative root resolves to an absolute path in the normalized config.
	rel, err := filepath.Rel(mustGetwd(t), dir)
	if err != nil {
		t.Skipf("cannot relativize temp dir: %v", err)
	}
	raw, err := (registry.FilesystemRegistration{}).Normalize("core.filesystem",
		json.RawMessage(`{"capabilities":[{"operation":"read"}],"roots":["`+filepath.ToSlash(rel)+`"]}`))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	var config struct {
		Roots        []string `json:"roots"`
		MaxReadBytes int64    `json:"max_read_bytes"`
		MaxLines     int      `json:"max_lines"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatalf("decode normalized: %v", err)
	}
	if len(config.Roots) != 1 || !filepath.IsAbs(config.Roots[0]) {
		t.Fatalf("roots = %v, want one absolute path", config.Roots)
	}
	if config.MaxReadBytes != filesystem.DefaultMaxReadBytes || config.MaxLines != filesystem.DefaultMaxLines {
		t.Fatalf("defaults not applied: %+v", config)
	}
}

func TestFilesystemRejectsBadConfig(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "afile")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"no roots":            `{"capabilities":[{"operation":"read"}]}`,
		"empty roots":         `{"capabilities":[{"operation":"read"}],"roots":[]}`,
		"missing root":        `{"capabilities":[{"operation":"read"}],"roots":["` + filepath.Join(dir, "nope") + `"]}`,
		"file as root":        `{"capabilities":[{"operation":"read"}],"roots":["` + file + `"]}`,
		"no capabilities":     `{"roots":["` + dir + `"]}`,
		"unknown op":          `{"capabilities":[{"operation":"write"}],"roots":["` + dir + `"]}`,
		"duplicate op":        `{"capabilities":[{"operation":"read"},{"operation":"read"}],"roots":["` + dir + `"]}`,
		"bad extension":       `{"capabilities":[{"operation":"read"}],"roots":["` + dir + `"],"extensions":["a/b"]}`,
		"unknown field":       `{"capabilities":[{"operation":"read"}],"roots":["` + dir + `"],"bogus":1}`,
		"negative read bytes": `{"capabilities":[{"operation":"read"}],"roots":["` + dir + `"],"max_read_bytes":-1}`,
	}
	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := (registry.FilesystemRegistration{}).Normalize("core.filesystem", json.RawMessage(config)); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
}

func TestFilesystemDescriptionNamesRoots(t *testing.T) {
	dir := t.TempDir()
	built, err := filesystemRegistry().Build(context.Background(),
		[]registry.Entry{{Syscall: "core.filesystem", Config: json.RawMessage(`{"capabilities":[{"operation":"read"}],"roots":["` + dir + `"]}`)}},
		registry.Services{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.Contains(built.Descriptors()[0].Description, dir) {
		t.Fatalf("description should name the root %q: %s", dir, built.Descriptors()[0].Description)
	}
	if !strings.Contains(built.Descriptors()[0].Description, "read") {
		t.Fatalf("description should mention the read operation: %s", built.Descriptors()[0].Description)
	}
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}
