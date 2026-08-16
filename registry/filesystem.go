package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-dispatchers/filesystem"
)

// filesystemConfig is a core.filesystem grant's driver configuration: the
// read-only operations it grants (each an ADT case with its data-flow policy),
// the roots it is chrooted to, and the read bounds. Roots are the security
// boundary — every path a guest names must resolve inside one.
type filesystemConfig struct {
	Capabilities   json.RawMessage `json:"capabilities,omitempty"`
	Roots          []string        `json:"roots,omitempty"`
	Extensions     []string        `json:"extensions,omitempty"`
	MaxReadBytes   int64           `json:"max_read_bytes,omitempty"`
	MaxLines       int             `json:"max_lines,omitempty"`
	FollowSymlinks bool            `json:"follow_symlinks,omitempty"`
}

// filesystemOperations are the cases a core.filesystem grant may enable, each
// with the field schema its args carry (minus the `operation` discriminator,
// which OperationBranch injects) and a one-line description. The capability is
// read-only for now, so `read` is the only case.
var filesystemOperations = map[string]struct {
	schema      json.RawMessage
	description string
}{
	"read": {
		schema:      json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","minLength":1},"start_line":{"type":"integer","minimum":1},"end_line":{"type":"integer","minimum":1}},"required":["path"],"additionalProperties":false}`),
		description: "read: read a file's UTF-8 text — the whole file, or an inclusive 1-based line range with start_line and/or end_line (path is absolute or relative to a root)",
	},
}

// FilesystemRegistration provides read-only host filesystem access — a
// root-chrooted, journaled capability whose reads carry the grant's provenance
// labels (see the filesystem package). It grants no writes.
type FilesystemRegistration struct{}

func (FilesystemRegistration) Matches(syscall string) bool { return syscall == filesystem.Capability }

func (FilesystemRegistration) Configure(_ context.Context, raw json.RawMessage, _ Services) (capability.Family, error) {
	config, grants, err := parseFilesystemConfig(raw)
	if err != nil {
		return capability.Family{}, err
	}

	operations := make(map[string]filesystem.Operation, len(grants))
	for _, grant := range grants {
		operations[grant.Operation] = filesystem.Operation{}
	}
	handler := filesystem.Handler{
		Name:           filesystem.Capability,
		Roots:          config.Roots,
		Extensions:     config.Extensions,
		MaxReadBytes:   config.MaxReadBytes,
		MaxLines:       config.MaxLines,
		FollowSymlinks: config.FollowSymlinks,
		Operations:     operations,
	}

	entries := make([]capability.Entry, 0, len(grants))
	branches := make([]json.RawMessage, 0, len(grants))
	names := make([]string, 0, len(grants))
	for _, grant := range grants {
		branch, err := OperationBranch(grant.Operation, filesystemOperations[grant.Operation].schema)
		if err != nil {
			return capability.Family{}, err
		}
		entries = append(entries, capability.Entry{
			Key:             capability.Key{Syscall: filesystem.Capability, Operation: grant.Operation},
			Discriminator:   "operation",
			Description:     filesystemOperations[grant.Operation].description,
			Input:           branch,
			Labels:          grant.Labels,
			Forbid:          grant.Taints,
			RequireApproval: grant.RequireApproval != nil && *grant.RequireApproval,
			Handler:         handler,
		})
		branches = append(branches, branch)
		names = append(names, filesystemOperations[grant.Operation].description)
	}

	return capability.Family{Entries: entries,
		Description: fmt.Sprintf("Read-only filesystem access under %s — paths are absolute or relative to a root, and never escape it. Choose an operation:\n- %s.",
			strings.Join(config.Roots, ", "), strings.Join(names, "\n- ")),
		Input: OneOfSchema(branches),
	}, nil
}

// parseFilesystemConfig validates and canonicalizes a core.filesystem grant's
// config — the single parse Normalize and Configure share. It rejects unknown
// top-level fields, requires at least one granted operation from the known set
// with no duplicates, normalizes each operation's flow policy, validates roots,
// and applies the default read bounds.
func parseFilesystemConfig(raw json.RawMessage) (filesystemConfig, []OperationGrant, error) {
	config := filesystemConfig{
		MaxReadBytes: filesystem.DefaultMaxReadBytes,
		MaxLines:     filesystem.DefaultMaxLines,
	}
	if len(raw) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config); err != nil {
			return filesystemConfig{}, nil, err
		}
	}
	grants, err := DecodeOperationGrants(config.Capabilities)
	if err != nil {
		return filesystemConfig{}, nil, err
	}
	if len(grants) == 0 {
		return filesystemConfig{}, nil, errors.New("capabilities must grant at least one operation (read)")
	}
	seen := make(map[string]struct{}, len(grants))
	for i := range grants {
		operation := strings.TrimSpace(grants[i].Operation)
		if _, ok := filesystemOperations[operation]; !ok {
			return filesystemConfig{}, nil, fmt.Errorf("unknown filesystem operation %q (want read)", grants[i].Operation)
		}
		if _, dup := seen[operation]; dup {
			return filesystemConfig{}, nil, fmt.Errorf("duplicate filesystem operation %q", operation)
		}
		seen[operation] = struct{}{}
		grants[i].Operation = operation
		if grants[i].FlowPolicy, err = grants[i].FlowPolicy.Normalized(); err != nil {
			return filesystemConfig{}, nil, fmt.Errorf("operation %q: %w", operation, err)
		}
	}
	sortOperationGrants(grants)

	if config.Roots, err = normalizeRoots(config.Roots); err != nil {
		return filesystemConfig{}, nil, err
	}
	if config.Extensions, err = normalizeExtensions(config.Extensions); err != nil {
		return filesystemConfig{}, nil, err
	}
	if config.MaxReadBytes <= 0 {
		return filesystemConfig{}, nil, errors.New("max_read_bytes must be positive")
	}
	if config.MaxLines <= 0 {
		return filesystemConfig{}, nil, errors.New("max_lines must be positive")
	}
	return config, grants, nil
}

// normalizeRoots requires at least one root and canonicalizes each to an
// existing absolute directory, de-duplicated and sorted.
func normalizeRoots(roots []string) ([]string, error) {
	if len(roots) == 0 {
		return nil, errors.New("roots must contain at least one directory")
	}
	out := make([]string, 0, len(roots))
	for _, root := range roots {
		abs, err := filepath.Abs(root)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(abs)
		if err != nil {
			return nil, fmt.Errorf("filesystem root %q: %w", root, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("filesystem root %q is not a directory", root)
		}
		abs = filepath.Clean(abs)
		if !slices.Contains(out, abs) {
			out = append(out, abs)
		}
	}
	slices.Sort(out)
	return out, nil
}

// normalizeExtensions lowercases each extension, ensures a leading dot, rejects
// path separators, and de-duplicates. An empty list allows any extension.
func normalizeExtensions(extensions []string) ([]string, error) {
	out := make([]string, 0, len(extensions))
	for _, extension := range extensions {
		extension = strings.ToLower(strings.TrimSpace(extension))
		if extension == "" {
			continue
		}
		if !strings.HasPrefix(extension, ".") {
			extension = "." + extension
		}
		if strings.ContainsAny(extension, `/\`) {
			return nil, fmt.Errorf("invalid extension %q", extension)
		}
		if !slices.Contains(out, extension) {
			out = append(out, extension)
		}
	}
	slices.Sort(out)
	return out, nil
}
