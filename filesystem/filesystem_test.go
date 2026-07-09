package filesystem_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/filesystem"
	"github.com/aurora-capcompute/capcompute/sys"
)

// handler builds a read-granting handler rooted at dir with default bounds.
func handler(dir string) filesystem.Handler {
	return filesystem.Handler{
		Name:         filesystem.Capability,
		Roots:        []string{dir},
		MaxReadBytes: filesystem.DefaultMaxReadBytes,
		MaxLines:     filesystem.DefaultMaxLines,
		Operations:   map[string]filesystem.Operation{"read": {}},
	}
}

// readArgs builds a read call's args from a fields object merged with the
// `operation` discriminator.
func readArgs(t *testing.T, fields string) json.RawMessage {
	t.Helper()
	m := map[string]json.RawMessage{}
	if fields != "" {
		if err := json.Unmarshal([]byte(fields), &m); err != nil {
			t.Fatalf("readArgs %q: %v", fields, err)
		}
	}
	m["operation"] = json.RawMessage(`"read"`)
	raw, _ := json.Marshal(m)
	return raw
}

func dispatch(t *testing.T, h filesystem.Handler, fields string) sys.SyscallResult {
	t.Helper()
	return dispatchCtx(t, context.Background(), h, fields, sys.Authorization{})
}

func dispatchCtx(t *testing.T, ctx context.Context, h filesystem.Handler, fields string, auth sys.Authorization) sys.SyscallResult {
	t.Helper()
	result, err := h.DispatchCall(ctx, sys.Syscall{Name: filesystem.Capability, Args: readArgs(t, fields)}, auth)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	return result
}

func decodeRead(t *testing.T, result sys.SyscallResult) filesystem.ReadResponse {
	t.Helper()
	if result.Status() != sys.StatusResult {
		t.Fatalf("status = %q (%s): %s", result.Status(), result.Errno(), result.Message())
	}
	var response filesystem.ReadResponse
	if err := json.Unmarshal(result.Result(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return response
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadWholeFile(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "notes.txt", "alpha\nbeta\ngamma\n")
	response := decodeRead(t, dispatch(t, handler(dir), `{"path":"notes.txt"}`))
	if response.Content != "alpha\nbeta\ngamma\n" {
		t.Fatalf("content = %q, want the file's exact bytes", response.Content)
	}
	if response.TotalLines != 3 || response.LineCount != 3 {
		t.Fatalf("lines = %d/%d, want 3/3", response.LineCount, response.TotalLines)
	}
	if response.StartLine != 1 || response.EndLine != 3 {
		t.Fatalf("range = %d..%d, want 1..3", response.StartLine, response.EndLine)
	}
	if response.Path != "notes.txt" {
		t.Fatalf("path = %q, want the root-relative display path", response.Path)
	}
	if response.Truncated {
		t.Fatal("whole small file should not be truncated")
	}
}

func TestReadNoTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "f", "a\nb\nc")
	response := decodeRead(t, dispatch(t, handler(dir), `{"path":"f"}`))
	if response.TotalLines != 3 {
		t.Fatalf("total = %d, want 3 (no trailing newline)", response.TotalLines)
	}
	if response.Content != "a\nb\nc" {
		t.Fatalf("content = %q, want exact bytes", response.Content)
	}
}

func TestReadLineRange(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "f", "one\ntwo\nthree\nfour\nfive\n")
	response := decodeRead(t, dispatch(t, handler(dir), `{"path":"f","start_line":2,"end_line":4}`))
	if response.Content != "two\nthree\nfour\n" {
		t.Fatalf("content = %q, want lines 2..4", response.Content)
	}
	if response.StartLine != 2 || response.EndLine != 4 || response.LineCount != 3 {
		t.Fatalf("range = %d..%d (%d lines), want 2..4 (3)", response.StartLine, response.EndLine, response.LineCount)
	}
	if response.TotalLines != 5 {
		t.Fatalf("total = %d, want 5", response.TotalLines)
	}
}

func TestReadOpenEndedRanges(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "f", "1\n2\n3\n4\n5\n")

	from := decodeRead(t, dispatch(t, handler(dir), `{"path":"f","start_line":3}`))
	if from.Content != "3\n4\n5\n" || from.StartLine != 3 || from.EndLine != 5 {
		t.Fatalf("start-only = %q %d..%d, want \"3\\n4\\n5\\n\" 3..5", from.Content, from.StartLine, from.EndLine)
	}

	upto := decodeRead(t, dispatch(t, handler(dir), `{"path":"f","end_line":2}`))
	if upto.Content != "1\n2\n" || upto.StartLine != 1 || upto.EndLine != 2 {
		t.Fatalf("end-only = %q %d..%d, want \"1\\n2\\n\" 1..2", upto.Content, upto.StartLine, upto.EndLine)
	}
}

func TestReadRangePastEOF(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "f", "1\n2\n3\n")

	clamped := decodeRead(t, dispatch(t, handler(dir), `{"path":"f","start_line":2,"end_line":99}`))
	if clamped.Content != "2\n3\n" || clamped.EndLine != 3 {
		t.Fatalf("clamped = %q end=%d, want \"2\\n3\\n\" end=3", clamped.Content, clamped.EndLine)
	}

	beyond := decodeRead(t, dispatch(t, handler(dir), `{"path":"f","start_line":10}`))
	if beyond.Content != "" || beyond.LineCount != 0 {
		t.Fatalf("start past EOF = %q (%d lines), want empty", beyond.Content, beyond.LineCount)
	}
	if beyond.TotalLines != 3 {
		t.Fatalf("total = %d, want 3", beyond.TotalLines)
	}
}

func TestReadLineCapTruncates(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "f", "a\nb\nc\nd\ne\n")
	h := handler(dir)
	h.MaxLines = 2
	response := decodeRead(t, dispatch(t, h, `{"path":"f"}`))
	if response.LineCount != 2 || response.EndLine != 2 {
		t.Fatalf("lines = %d end=%d, want 2 lines ending at 2", response.LineCount, response.EndLine)
	}
	if !response.Truncated {
		t.Fatal("line cap should flag truncated")
	}
	if response.Content != "a\nb\n" {
		t.Fatalf("content = %q, want first two lines", response.Content)
	}
}

func TestReadByteCapTruncates(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "f", "aaaa\nbbbb\ncccc\n")
	h := handler(dir)
	h.MaxReadBytes = 7 // cuts inside the second line
	response := decodeRead(t, dispatch(t, h, `{"path":"f"}`))
	if !response.Truncated {
		t.Fatal("byte cap should flag truncated")
	}
	// Only the first complete line survives; the partial line is dropped.
	if response.Content != "aaaa\n" {
		t.Fatalf("content = %q, want only the first complete line", response.Content)
	}
}

func TestReadInvalidRange(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "f", "x\n")
	result := dispatch(t, handler(dir), `{"path":"f","start_line":5,"end_line":2}`)
	if result.Status() != sys.StatusFailed || result.Errno() != sys.ErrnoInvalidArgs {
		t.Fatalf("status = %q errno = %q, want failed/invalid_args", result.Status(), result.Errno())
	}
}

func TestReadMissingFile(t *testing.T) {
	dir := t.TempDir()
	result := dispatch(t, handler(dir), `{"path":"nope.txt"}`)
	if result.Status() != sys.StatusFailed || result.Errno() != sys.ErrnoNotFound {
		t.Fatalf("status = %q errno = %q, want failed/not_found", result.Status(), result.Errno())
	}
}

func TestReadRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "sub/inner.txt", "hi\n")
	result := dispatch(t, handler(dir), `{"path":"sub"}`)
	if result.Status() != sys.StatusFailed {
		t.Fatalf("reading a directory should fail: %s", result.Result())
	}
	if !strings.Contains(result.Message(), "directory") {
		t.Fatalf("message = %q, want a directory error", result.Message())
	}
}

func TestReadRejectsEscape(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	// A secret beside, but outside, the root.
	write(t, filepath.Dir(root), "secret.txt", "top secret\n")

	for _, path := range []string{"../secret.txt", filepath.Join(filepath.Dir(root), "secret.txt")} {
		args, _ := json.Marshal(map[string]string{"path": path})
		result := dispatch(t, handler(root), string(args))
		if result.Status() != sys.StatusFailed {
			t.Fatalf("path %q escaped the root: %s", path, result.Result())
		}
	}
}

func TestReadExtensionAllowlist(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.md", "# ok\n")
	write(t, dir, "b.exe", "nope\n")
	h := handler(dir)
	h.Extensions = []string{".md"}

	if got := decodeRead(t, dispatch(t, h, `{"path":"a.md"}`)); got.TotalLines != 1 {
		t.Fatalf("allowed extension should read: %+v", got)
	}
	result := dispatch(t, h, `{"path":"b.exe"}`)
	if result.Status() != sys.StatusFailed || !strings.Contains(result.Message(), "extension") {
		t.Fatalf("disallowed extension should fail: %q", result.Message())
	}
}

func TestReadRejectsBinary(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "b.bin", "ok\x00nul")
	result := dispatch(t, handler(dir), `{"path":"b.bin"}`)
	if result.Status() != sys.StatusFailed || result.Errno() != sys.ErrnoInvalidArgs {
		t.Fatalf("binary content should fail invalid_args: %q %q", result.Errno(), result.Message())
	}
}

func TestReadUngrantedOperation(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "f", "x\n")
	h := handler(dir)
	h.Operations = map[string]filesystem.Operation{} // grant nothing
	result := dispatch(t, h, `{"path":"f"}`)
	if result.Status() != sys.StatusFailed || result.Errno() != sys.ErrnoDenied {
		t.Fatalf("ungranted read should be denied: %q %q", result.Errno(), result.Message())
	}
}

func TestReadRequiresApproval(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "f", "secret\n")
	h := handler(dir)
	h.Operations = map[string]filesystem.Operation{"read": {RequireApproval: true}}

	pending := dispatch(t, h, `{"path":"f"}`)
	if pending.Status() != sys.StatusYield {
		t.Fatalf("status = %q, want yield awaiting approval", pending.Status())
	}
	approved := dispatchCtx(t, context.Background(), h, `{"path":"f"}`, sys.Authorization{Decision: sys.Approved})
	if got := decodeRead(t, approved); got.Content != "secret\n" {
		t.Fatalf("approved read = %q, want the file content", got.Content)
	}
}

func TestReadStampsLabels(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "f", "data\n")
	h := handler(dir)
	h.Operations = map[string]filesystem.Operation{"read": {Labels: []string{"untrusted_file"}}}
	result := dispatch(t, h, `{"path":"f"}`)
	if labels := result.Labels(); len(labels) != 1 || labels[0] != "untrusted_file" {
		t.Fatalf("labels = %v, want [untrusted_file] — file contents are a tainted source", labels)
	}
}

func TestReadSinkGuardBlocksTaint(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "f", "data\n")
	h := handler(dir)
	h.Operations = map[string]filesystem.Operation{"read": {Taints: []string{"secret"}}}
	ctx := sys.WithTaint(context.Background(), []string{"secret"})
	result := dispatchCtx(t, ctx, h, `{"path":"f"}`, sys.Authorization{})
	if result.Status() != sys.StatusFailed || result.Errno() != sys.ErrnoDenied {
		t.Fatalf("a run tainted with a forbidden label must be refused: %q %q", result.Errno(), result.Message())
	}
}

func TestReadFollowsAbsolutePathInsideRoot(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "sub/f.txt", "hi\n")
	abs := filepath.Join(dir, "sub", "f.txt")
	args, _ := json.Marshal(map[string]string{"path": abs})
	response := decodeRead(t, dispatch(t, handler(dir), string(args)))
	if response.Content != "hi\n" {
		t.Fatalf("absolute path inside the root should read: %q", response.Content)
	}
	if response.Path != "sub/f.txt" {
		t.Fatalf("display path = %q, want sub/f.txt", response.Path)
	}
}

func TestReadRejectsSymlinkByDefault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	dir := t.TempDir()
	write(t, dir, "real.txt", "real\n")
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(filepath.Join(dir, "real.txt"), link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	result := dispatch(t, handler(dir), `{"path":"link.txt"}`)
	if result.Status() != sys.StatusFailed || !strings.Contains(result.Message(), "symlink") {
		t.Fatalf("symlink should be rejected by default: %q", result.Message())
	}

	h := handler(dir)
	h.FollowSymlinks = true
	if got := decodeRead(t, dispatch(t, h, `{"path":"link.txt"}`)); got.Content != "real\n" {
		t.Fatalf("follow_symlinks should read the target: %q", got.Content)
	}
}

func TestReadRejectsIntermediateSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	dir := t.TempDir()
	write(t, dir, "real/secret.txt", "secret\n")
	if err := os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	// follow=false: a symlink anywhere on the path — here an intermediate
	// directory — is rejected, not just a final-component link.
	result := dispatch(t, handler(dir), `{"path":"link/secret.txt"}`)
	if result.Status() != sys.StatusFailed || !strings.Contains(result.Message(), "symlink") {
		t.Fatalf("intermediate symlink should be rejected: %q %q", result.Errno(), result.Message())
	}
	// follow=true: it is resolved, and the target still lands inside the root.
	h := handler(dir)
	h.FollowSymlinks = true
	if got := decodeRead(t, dispatch(t, h, `{"path":"link/secret.txt"}`)); got.Content != "secret\n" {
		t.Fatalf("follow_symlinks should read through an intermediate link: %q", got.Content)
	}
}

func TestReadSymlinkEscapeWithFollow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	root := filepath.Join(t.TempDir(), "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(filepath.Dir(root), "outside.txt")
	if err := os.WriteFile(outside, []byte("no\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link.txt")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	// Even with following enabled, a symlink whose target leaves the root is
	// refused — the real path is what must be contained.
	h := handler(root)
	h.FollowSymlinks = true
	result := dispatch(t, h, `{"path":"link.txt"}`)
	if result.Status() != sys.StatusFailed || !strings.Contains(result.Message(), "escapes") {
		t.Fatalf("a symlink escaping the root must fail even with follow: %q %q", result.Errno(), result.Message())
	}
}
