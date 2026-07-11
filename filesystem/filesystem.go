// Package filesystem provides read-only access to the host filesystem as a
// journaled capability — the OS-model rule that a guest touches the disk only
// through a scoped, replayable syscall, never ambiently (see capcompute
// docs/ARCHITECTURE.md, "No ambient authority"). A grant is chrooted to one or
// more roots: every path a guest names, absolute or relative, must resolve
// inside a root, and symlink escapes are rejected rather than followed. Reads
// are deterministic — the recorded result replays regardless of later disk
// mutations — and carry the grant's provenance labels, so file contents enter
// the flow monitor tainted at their source (the file-poisoning defense),
// exactly like tenant memory and the network.
//
// The capability is read-only for now: its operations are cases of one
// discriminated ADT selected by the `operation` field, and `read` is the only
// case. Mutating operations, if ever added, are new cases of this same
// capability, never separate names.
package filesystem

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aurora-capcompute/capcompute/sys"
)

// Capability is the name a core.filesystem grant publishes — the syscall's own
// name. Its operations (read) are cases of one discriminated ADT, selected by
// the `operation` field in the call args, not separate capability names.
const Capability = "core.filesystem"

// Default bounds for a grant that does not set its own.
const (
	// DefaultMaxReadBytes caps how much of a file a single read pulls into
	// context; a larger file is served up to the cap and flagged truncated.
	DefaultMaxReadBytes int64 = 2 << 20 // 2 MiB
	// DefaultMaxLines caps how many lines one read returns.
	DefaultMaxLines int = 10000
)

// ReadRequest reads one file, whole or by an inclusive 1-based line range.
// A zero StartLine means "from the first line"; a zero EndLine means "to the
// last line", so an omitted range reads the whole file.
type ReadRequest struct {
	Operation string `json:"operation"`
	Path      string `json:"path"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
}

// ReadResponse is the result of a read: the (possibly line-sliced) content,
// the range and totals that locate it in the file, and the whole file's hash
// so a later revision can detect that the file changed under it.
type ReadResponse struct {
	Path       string `json:"path"`
	Content    string `json:"content"`
	StartLine  int    `json:"start_line"`
	EndLine    int    `json:"end_line"`
	LineCount  int    `json:"line_count"`
	TotalLines int    `json:"total_lines"`
	Bytes      int    `json:"bytes"`
	Hash       string `json:"hash"`
	// Truncated reports that a byte or line cap stopped the read before the
	// requested range was fully returned.
	Truncated bool `json:"truncated,omitempty"`
}

// Operation is one granted filesystem case's policy: whether it needs human
// approval, the source classes its results carry (Labels — file contents are an
// external source, tainted at entry), and the labels it refuses to let flow in
// (Taints, the sink guard).
type Operation struct {
	RequireApproval bool
	Labels          []string
	Taints          []string
}

// Handler serves one core.filesystem grant: the roots it is chrooted to, the
// read bounds, and the granted operations. It satisfies builtin.Handler and
// publishes the single core.filesystem capability. Roots and bounds are
// host-side grant parameters — a guest only ever names paths that resolve
// inside a root.
type Handler struct {
	// Name is the published capability name (core.filesystem).
	Name string
	// Roots are the absolute directories a grant may read within. Required.
	Roots []string
	// Extensions optionally restricts reads to these lowercased extensions
	// (each with a leading dot); empty allows any extension.
	Extensions []string
	// MaxReadBytes caps the bytes one read pulls from a file.
	MaxReadBytes int64
	// MaxLines caps the lines one read returns.
	MaxLines int
	// FollowSymlinks resolves symlinks (still confined to a root) instead of
	// rejecting them.
	FollowSymlinks bool
	// Operations are the granted cases keyed by operation name (read); an
	// operation absent here is not granted. Each carries its approval
	// requirement and data-flow policy.
	Operations map[string]Operation
}

func (h Handler) Handles(name string) bool { return name == h.Name }

func (h Handler) DispatchCall(ctx context.Context, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if len(h.Roots) == 0 {
		return sys.FailCode(sys.ErrnoInternal, "filesystem grant has no roots"), nil
	}
	operation, err := peekOperation(call.Args)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
	}
	op, granted := h.Operations[operation]
	if !granted {
		return sys.FailCode(sys.ErrnoDenied, fmt.Sprintf("filesystem operation %q is not granted", operation)), nil
	}
	// Sink guard: refuse before the read if the run has observed a label this
	// operation forbids. Deterministic on replay — the taint is rebuilt from the
	// journal identically.
	if blocked := sys.BlockedBy(sys.Taint(ctx), op.Taints); len(blocked) > 0 {
		return sys.FailCode(sys.ErrnoDenied, fmt.Sprintf(
			"flow policy: this run has observed %v, which may not flow into filesystem %q", blocked, operation)), nil
	}
	var result sys.SyscallResult
	switch operation {
	case "read":
		result, err = h.read(ctx, call, auth, op.RequireApproval)
	default:
		return sys.FailCode(sys.ErrnoNotFound, "unknown filesystem operation: "+operation), nil
	}
	if err != nil || result.Status() != sys.StatusResult {
		return result, err
	}
	// Stamp the operation's source labels so file contents enter the flow
	// monitor tainted at their origin.
	return result.WithLabels(op.Labels...), nil
}

// peekOperation reads the ADT discriminator from a filesystem call's args.
func peekOperation(args json.RawMessage) (string, error) {
	var envelope struct {
		Operation string `json:"operation"`
	}
	if err := json.Unmarshal(args, &envelope); err != nil {
		return "", fmt.Errorf("decode operation: %v", err)
	}
	if envelope.Operation == "" {
		return "", errors.New("operation is required")
	}
	return envelope.Operation, nil
}

func (h Handler) read(ctx context.Context, call sys.Syscall, auth sys.Authorization, requireApproval bool) (sys.SyscallResult, error) {
	var request ReadRequest
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", call.Name, err)), nil
	}
	if request.StartLine < 0 || request.EndLine < 0 {
		return sys.FailCode(sys.ErrnoInvalidArgs, "start_line and end_line must be positive"), nil
	}
	if request.StartLine > 0 && request.EndLine > 0 && request.StartLine > request.EndLine {
		return sys.FailCode(sys.ErrnoInvalidArgs, "start_line must not exceed end_line"), nil
	}
	path, display, err := h.resolve(request.Path)
	if err != nil {
		return failure(ctx, err)
	}
	if requireApproval && auth.Decision != sys.Approved {
		return sys.Yield(fmt.Sprintf("Approve reading %s", display)), nil
	}
	data, capped, err := readCapped(path, h.MaxReadBytes)
	if err != nil {
		return failure(ctx, err)
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return sys.FailCode(sys.ErrnoInvalidArgs, "binary content is not supported"), nil
	}
	return marshalResult(buildReadResponse(display, data, capped, request.StartLine, request.EndLine, h.MaxLines))
}

// buildReadResponse slices the read bytes to the requested line range, applies
// the line cap, and assembles the response. Lines are 1-based and inclusive; a
// zero start or end means the file's first or last line.
func buildReadResponse(display string, data []byte, dataTruncated bool, startLine, endLine, maxLines int) ReadResponse {
	text := string(data)
	lines := splitLines(text, dataTruncated)
	total := len(lines)

	start := startLine
	if start <= 0 {
		start = 1
	}
	end := endLine
	if end <= 0 || end > total {
		end = total
	}
	truncated := dataTruncated
	if end-start+1 > maxLines {
		end = start + maxLines - 1
		truncated = true
	}

	response := ReadResponse{Path: display, TotalLines: total, Hash: hashBytes(data)}
	if total == 0 || start > total {
		// Empty file, or a range that starts past the last line: no content.
		response.Truncated = truncated
		return response
	}
	selected := lines[start-1 : end]
	wholeFile := startLine <= 0 && endLine <= 0 && !truncated
	var content string
	if wholeFile {
		// Return the file's exact bytes when the whole file fits — line
		// splitting is lossy about the final newline, and callers hashing or
		// diffing the content expect the original.
		content = text
	} else {
		content = strings.Join(selected, "\n") + "\n"
	}
	response.Content = content
	response.Bytes = len(content)
	response.StartLine = start
	response.EndLine = end
	response.LineCount = len(selected)
	response.Truncated = truncated
	return response
}

// splitLines splits file text into lines, dropping the trailing element a final
// newline produces so "a\n" is one line, not two. When the read was byte-capped
// mid-file the final element is instead a possibly-partial line, so it is
// dropped as well — a read never returns half a line.
func splitLines(text string, dataTruncated bool) []string {
	if text == "" {
		return nil
	}
	lines := strings.Split(text, "\n")
	if last := len(lines) - 1; last >= 0 && (lines[last] == "" || dataTruncated) {
		lines = lines[:last]
	}
	return lines
}

// resolve maps a guest path to an absolute file inside a root and its display
// path (relative to that root). Absolute paths must already fall inside a root;
// relative paths are tried against each root. When the grant does not follow
// symlinks, any symlink on the path — final or intermediate — is rejected; when
// it does, the whole path is resolved and the real target must still land inside
// a root. Directories and non-regular files are refused: this capability reads
// files.
func (h Handler) resolve(input string) (string, string, error) {
	if strings.TrimSpace(input) == "" {
		return "", "", errors.New("path is required")
	}
	var candidates []string
	if filepath.IsAbs(input) {
		candidates = []string{filepath.Clean(input)}
	} else {
		for _, root := range h.Roots {
			candidates = append(candidates, filepath.Join(root, filepath.Clean(input)))
		}
	}
	for _, candidate := range candidates {
		if containingRoot(candidate, h.Roots) == "" {
			continue
		}
		if _, err := os.Lstat(candidate); err != nil {
			continue // not here; try the next root
		}
		if h.FollowSymlinks {
			// Resolve every symlink on the path and require the real target to
			// stay inside a root.
			resolved, err := filepath.EvalSymlinks(candidate)
			if err != nil {
				return "", "", err
			}
			root := containingRoot(resolved, h.Roots)
			if root == "" {
				return "", "", errors.New("symlink escapes filesystem roots")
			}
			return h.finishResolve(root, resolved)
		}
		// Reject any symlink on the path so a link cannot redirect the read out
		// of the root.
		root := containingRoot(candidate, h.Roots)
		if err := rejectSymlinks(root, candidate); err != nil {
			return "", "", err
		}
		return h.finishResolve(root, candidate)
	}
	return "", "", os.ErrNotExist
}

// finishResolve confirms path — already inside root and free of disallowed
// symlinks — is a readable regular file of an allowed extension, and returns it
// with its root-relative display path.
func (h Handler) finishResolve(root, path string) (string, string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", "", err
	}
	if info.IsDir() {
		return "", "", errors.New("path is a directory; filesystem read serves regular files")
	}
	if !info.Mode().IsRegular() {
		return "", "", errors.New("path is not a regular file")
	}
	if !h.extensionAllowed(path) {
		return "", "", fmt.Errorf("extension %q is not allowed", strings.ToLower(filepath.Ext(path)))
	}
	rel, _ := filepath.Rel(root, path)
	return path, filepath.ToSlash(rel), nil
}

func (h Handler) extensionAllowed(path string) bool {
	if len(h.Extensions) == 0 {
		return true
	}
	extension := strings.ToLower(filepath.Ext(path))
	for _, allowed := range h.Extensions {
		if extension == allowed {
			return true
		}
	}
	return false
}

// containingRoot returns the first root that contains path, or "" if none does.
func containingRoot(path string, roots []string) string {
	path = filepath.Clean(path)
	for _, root := range roots {
		rel, err := filepath.Rel(root, path)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return root
		}
	}
	return ""
}

// errSymlink is returned when a symlink lies on a path the grant does not follow.
// It carries no filesystem path so a read never leaks an absolute host path.
var errSymlink = errors.New("symlink traversal is disabled")

// rejectSymlinks walks every segment from root to path and fails with errSymlink
// if any is a symlink, so a symlinked component — final or intermediate — cannot
// redirect a read out of the root when symlink following is disabled.
func rejectSymlinks(root, path string) error {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return err
	}
	current := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errSymlink
		}
	}
	return nil
}

// readCapped reads up to limit bytes of a regular file, reporting whether the
// file was larger than the cap (and so was truncated).
func readCapped(path string, limit int64) ([]byte, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, errors.New("path is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}

// failure classifies a resolve/read error into a guest-visible failure,
// preferring the context error when the call was cancelled.
func failure(ctx context.Context, err error) (sys.SyscallResult, error) {
	if ctx.Err() != nil {
		return sys.SyscallResult{}, ctx.Err()
	}
	switch {
	case errors.Is(err, os.ErrNotExist):
		return sys.FailCode(sys.ErrnoNotFound, "no such file"), nil
	case errors.Is(err, os.ErrPermission):
		return sys.FailCode(sys.ErrnoDenied, scrubPath(err)), nil
	default:
		return sys.FailCode(sys.ErrnoInvalidArgs, scrubPath(err)), nil
	}
}

// scrubPath returns an error's message with any absolute host path removed. The
// os.Open/os.Stat/filepath.EvalSymlinks calls return an *os.PathError whose text
// embeds the absolute path (root joined with the guest's relative path); the
// guest is never shown absolute paths anywhere else (reads and approval prompts
// use the root-relative display path), so an error string must not disclose the
// mount point either. The underlying error ("permission denied", "is a
// directory") is kept — only the path is dropped.
func scrubPath(err error) string {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err.Error()
	}
	return err.Error()
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func marshalResult(value any) (sys.SyscallResult, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return sys.SyscallResult{}, err
	}
	return sys.Result(raw), nil
}
