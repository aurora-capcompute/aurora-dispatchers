package command

// These tests run real processes. That is deliberate: the guarantees this
// driver makes are about what the operating system is asked to do, and a fake
// exec would test the fake.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aurora-capcompute/capcompute/sys"
)

func anchored(t *testing.T, expr string) *regexp.Regexp {
	t.Helper()
	compiled, err := regexp.Compile(`\A(?:` + expr + `)\z`)
	if err != nil {
		t.Fatalf("compile %q: %v", expr, err)
	}
	return compiled
}

// echoCommand prints its arguments, one per line, so a test can see exactly
// what argv the child received.
func echoCommand(t *testing.T) Command {
	t.Helper()
	return Command{
		Name: "kubectl-get",
		Path: "/bin/echo",
		Args: []string{"--context={context}", "get", "{resource}"},
		Params: map[string]Param{
			"context":  {OneOf: []string{"prod-eu", "staging"}},
			"resource": {Pattern: anchored(t, `[a-z][a-z0-9]*`), Source: `[a-z][a-z0-9]*`},
		},
	}
}

func dispatch(t *testing.T, h Handler, args string) sys.SyscallResult {
	t.Helper()
	result, err := h.DispatchCall(context.Background(), sys.Syscall{
		Name: Capability,
		Args: json.RawMessage(args),
	}, sys.Authorization{Decision: sys.Approved})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	return result
}

func decode(t *testing.T, result sys.SyscallResult) Response {
	t.Helper()
	var response Response
	if err := json.Unmarshal(result.Result(), &response); err != nil {
		t.Fatalf("decode response: %v (%s)", err, result.Result())
	}
	return response
}

// A granted call runs, and the child receives the host's argv with the guest's
// values substituted — each as one element, never re-parsed.
func TestRunSubstitutesDeclaredSlots(t *testing.T) {
	h := Handler{Name: Capability, Commands: []Command{echoCommand(t)}}
	result := dispatch(t, h, `{"operation":"kubectl-get","params":{"context":"prod-eu","resource":"pods"}}`)
	if result.Status() != sys.StatusResult {
		t.Fatalf("run => %v (%s)", result.Status(), result.Message())
	}
	response := decode(t, result)
	if response.ExitCode != 0 {
		t.Fatalf("exit = %d", response.ExitCode)
	}
	if got := strings.TrimSpace(response.Stdout); got != "--context=prod-eu get pods" {
		t.Fatalf("child received %q", got)
	}
}

// The context is a closed set, so only its members are admitted — and a value
// that merely contains a member is not a member. An unanchored pattern would
// have admitted the last two of these.
func TestClosedSetAdmitsOnlyItsMembers(t *testing.T) {
	h := Handler{Name: Capability, Commands: []Command{echoCommand(t)}}
	for _, context := range []string{"prod-eu", "staging"} {
		args := `{"operation":"kubectl-get","params":{"context":"` + context + `","resource":"pods"}}`
		if result := dispatch(t, h, args); result.Status() != sys.StatusResult {
			t.Fatalf("context %q must be admitted: %s", context, result.Message())
		}
	}
	for _, context := range []string{"prod", "prod-eu-evil", "not-prod-eu", "PROD-EU", "", "dev"} {
		args := `{"operation":"kubectl-get","params":{"context":"` + context + `","resource":"pods"}}`
		if result := dispatch(t, h, args); result.Status() != sys.StatusFailed {
			t.Fatalf("context %q must be refused, got %v", context, result.Status())
		}
	}
}

// No parameter may become a flag. This is the guard that keeps a read-only
// wrapper read-only: `kubectl get -o go-template=...` and `git -c
// core.sshCommand=...` are both reached by a value that starts with a dash.
func TestParameterMayNotBecomeAFlag(t *testing.T) {
	free := Command{
		Name:   "echo",
		Path:   "/bin/echo",
		Args:   []string{"{value}"},
		Params: map[string]Param{"value": {Pattern: anchored(t, `.*`), Source: `.*`}},
	}
	h := Handler{Name: Capability, Commands: []Command{free}}
	// The slot's own pattern admits anything; the flag guard still refuses these.
	for _, value := range []string{"-o", "--output=json", "-c core.sshCommand=x", "-rf"} {
		args, _ := json.Marshal(Request{Operation: "echo", Params: map[string]string{"value": value}})
		result := dispatch(t, h, string(args))
		if result.Status() != sys.StatusFailed {
			t.Fatalf("value %q must be refused as a flag, got %v", value, result.Status())
		}
		if !strings.Contains(result.Message(), "flag") {
			t.Fatalf("refusal of %q should say why: %s", value, result.Message())
		}
	}
}

// There is no shell, so shell syntax in a parameter is inert: it arrives at the
// child as literal text in one argv element. This is the property that makes
// injection absent rather than filtered.
func TestShellMetacharactersAreInert(t *testing.T) {
	free := Command{
		Name:   "echo",
		Path:   "/bin/echo",
		Args:   []string{"{value}"},
		Params: map[string]Param{"value": {Pattern: anchored(t, `.*`), Source: `.*`}},
	}
	h := Handler{Name: Capability, Commands: []Command{free}}
	for _, value := range []string{
		"a; rm -rf /tmp/nope",
		"a && whoami",
		"a | tee /tmp/nope",
		"$(whoami)",
		"`whoami`",
		"*",
	} {
		args, _ := json.Marshal(Request{Operation: "echo", Params: map[string]string{"value": value}})
		result := dispatch(t, h, string(args))
		if result.Status() != sys.StatusResult {
			t.Fatalf("value %q => %v (%s)", value, result.Status(), result.Message())
		}
		if got := strings.TrimSuffix(decode(t, result).Stdout, "\n"); got != value {
			t.Fatalf("value %q reached the child as %q; it must arrive verbatim", value, got)
		}
	}
}

// Control characters are refused: a value spanning lines would corrupt the
// approval prompt a human reads and the audit record of what ran.
func TestControlCharactersAreRefused(t *testing.T) {
	free := Command{
		Name:   "echo",
		Path:   "/bin/echo",
		Args:   []string{"{value}"},
		Params: map[string]Param{"value": {Pattern: anchored(t, `(?s).*`), Source: `(?s).*`}},
	}
	h := Handler{Name: Capability, Commands: []Command{free}}
	for _, value := range []string{"a\nb", "a\rb", "a\tb", "a\x00b", "a\x1bb"} {
		args, _ := json.Marshal(Request{Operation: "echo", Params: map[string]string{"value": value}})
		result := dispatch(t, h, string(args))
		if result.Status() != sys.StatusFailed {
			t.Fatalf("value %q must be refused, got %v", value, result.Status())
		}
		if !strings.Contains(result.Message(), "control character") {
			t.Fatalf("refusal of %q should say why: %s", value, result.Message())
		}
	}
}

// A guest may not name a command it was not granted, nor pass a parameter the
// command did not declare, nor omit one it did.
func TestAllowlistAndSlotDiscipline(t *testing.T) {
	h := Handler{Name: Capability, Commands: []Command{echoCommand(t)}}
	cases := []struct {
		name  string
		args  string
		errno sys.Errno
	}{
		{"ungranted operation", `{"operation":"rm","params":{}}`, sys.ErrnoDenied},
		{"absent operation", `{"params":{}}`, sys.ErrnoDenied},
		{"undeclared parameter", `{"operation":"kubectl-get","params":{"context":"staging","resource":"pods","extra":"x"}}`, sys.ErrnoInvalidArgs},
		{"missing parameter", `{"operation":"kubectl-get","params":{"context":"staging"}}`, sys.ErrnoInvalidArgs},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			result := dispatch(t, h, test.args)
			if result.Status() != sys.StatusFailed || result.Errno() != test.errno {
				t.Fatalf("got %v/%v, want failed/%v: %s", result.Status(), result.Errno(), test.errno, result.Message())
			}
		})
	}
}

// The child's environment is exactly what the command declared — the host's is
// never inherited, so its secrets and its PATH are not reachable.
func TestEnvironmentIsNotInherited(t *testing.T) {
	t.Setenv("AURORA_COMMAND_SECRET", "must-not-leak")
	script := filepath.Join(t.TempDir(), "env.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nenv\n"), 0o700); err != nil {
		t.Fatalf("write script: %v", err)
	}
	h := Handler{Name: Capability, Commands: []Command{{
		Name: "show-env",
		Path: "/bin/sh",
		Args: []string{script},
		Env:  map[string]string{"KUBECONFIG": "/etc/aurora/kubeconfig"},
	}}}
	result := dispatch(t, h, `{"operation":"show-env","params":{}}`)
	if result.Status() != sys.StatusResult {
		t.Fatalf("run => %v (%s)", result.Status(), result.Message())
	}
	stdout := decode(t, result).Stdout
	if strings.Contains(stdout, "must-not-leak") || strings.Contains(stdout, "AURORA_COMMAND_SECRET") {
		t.Fatalf("the host environment leaked into the child:\n%s", stdout)
	}
	if !strings.Contains(stdout, "KUBECONFIG=/etc/aurora/kubeconfig") {
		t.Fatalf("the declared environment did not reach the child:\n%s", stdout)
	}
}

// A command that outruns its deadline is killed, and so is the process tree it
// started — a child holding the output pipe must not outlive the call.
func TestTimeoutKillsTheProcessGroup(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "survivor")
	script := filepath.Join(t.TempDir(), "spawn.sh")
	// Background a child that would create the marker well after the deadline,
	// then sleep past the deadline ourselves.
	body := "#!/bin/sh\n(sleep 5; touch " + marker + ") &\nsleep 5\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatalf("write script: %v", err)
	}
	h := Handler{Name: Capability, Commands: []Command{{
		Name:    "slow",
		Path:    "/bin/sh",
		Args:    []string{script},
		Timeout: 200 * time.Millisecond,
	}}}

	start := time.Now()
	result := dispatch(t, h, `{"operation":"slow","params":{}}`)
	elapsed := time.Since(start)
	if result.Status() != sys.StatusFailed {
		t.Fatalf("a timed-out command must fail, got %v", result.Status())
	}
	if elapsed > 4*time.Second {
		t.Fatalf("the call took %s; the deadline must bound it", elapsed)
	}
	// Give the orphan its chance to fire; if the group was killed it never will.
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a backgrounded child survived the timeout: the process group was not killed")
	}
}

// Output is bounded, and a command that overflows says so rather than filling
// the context window or being silently cut.
func TestOutputIsBounded(t *testing.T) {
	script := filepath.Join(t.TempDir(), "flood.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nyes aurora | head -c 200000\n"), 0o700); err != nil {
		t.Fatalf("write script: %v", err)
	}
	h := Handler{Name: Capability, Commands: []Command{{
		Name:           "flood",
		Path:           "/bin/sh",
		Args:           []string{script},
		MaxOutputBytes: 1024,
	}}}
	result := dispatch(t, h, `{"operation":"flood","params":{}}`)
	if result.Status() != sys.StatusResult {
		t.Fatalf("run => %v (%s)", result.Status(), result.Message())
	}
	response := decode(t, result)
	if len(response.Stdout) > 1024 {
		t.Fatalf("stdout is %d bytes, past the 1024 bound", len(response.Stdout))
	}
	if !response.Truncated {
		t.Fatal("truncation must be reported, not silent")
	}
}

// A non-zero exit is the command's own verdict: it comes back as a failure
// carrying the command's stderr, so the model can read what went wrong.
func TestNonZeroExitSurfacesStderr(t *testing.T) {
	script := filepath.Join(t.TempDir(), "fail.sh")
	if err := os.WriteFile(script, []byte(`#!/bin/sh`+"\n"+`echo "no such namespace" >&2`+"\n"+`exit 3`+"\n"), 0o700); err != nil {
		t.Fatalf("write script: %v", err)
	}
	h := Handler{Name: Capability, Commands: []Command{{Name: "failing", Path: "/bin/sh", Args: []string{script}}}}
	result := dispatch(t, h, `{"operation":"failing","params":{}}`)
	if result.Status() != sys.StatusFailed {
		t.Fatalf("a non-zero exit must fail, got %v", result.Status())
	}
	if !strings.Contains(result.Message(), "no such namespace") || !strings.Contains(result.Message(), "3") {
		t.Fatalf("the failure must carry the exit code and stderr: %q", result.Message())
	}
}

// A timeout and a command that never started are different failures: the first
// may well pass on a retry, the second is a configuration fault that will not.
func TestTimeoutIsTransientAndStartFailureIsNot(t *testing.T) {
	slow := Command{Name: "slow", Path: "/bin/sleep", Args: []string{"5"}, Timeout: 150 * time.Millisecond}
	h := Handler{Name: Capability, Commands: []Command{slow}}
	result := dispatch(t, h, `{"operation":"slow","params":{}}`)
	if result.Errno() != sys.ErrnoTransient {
		t.Fatalf("timeout errno = %v, want transient (a retry may succeed)", result.Errno())
	}

	missing := Command{Name: "missing", Path: "/nonexistent/aurora/binary"}
	h = Handler{Name: Capability, Commands: []Command{missing}}
	result = dispatch(t, h, `{"operation":"missing","params":{}}`)
	if result.Errno() != sys.ErrnoInternal {
		t.Fatalf("missing-binary errno = %v, want internal (retrying will not fix it)", result.Errno())
	}
}

// The executable must be absolute where it runs, not only where it was
// configured: a relative path would resolve against the working directory or
// PATH, the ambient authority this driver refuses to depend on. The registry
// checks it too; this is the floor under a Handler built by hand.
func TestRelativeExecutableIsRefusedAtRunTime(t *testing.T) {
	h := Handler{Name: Capability, Commands: []Command{{Name: "relative", Path: "echo"}}}
	result := dispatch(t, h, `{"operation":"relative","params":{}}`)
	if result.Status() != sys.StatusFailed {
		t.Fatalf("a relative executable must be refused, got %v", result.Status())
	}
	if !strings.Contains(result.Message(), "absolute") {
		t.Fatalf("the refusal should say why: %s", result.Message())
	}
}

// Approval and the sink guard used to be enforced here and are now the entry's:
// approval in builtin's dispatcher, flow policy in the runtime's monitor. They
// are tested where they are enforced — builtin/dispatcher_test.go and
// monitor/provenance_test.go — so this package tests only the effect.

// An empty value is refused for the same reason a leading dash is: it changes
// what the argument means. "--namespace={ns}" with an empty ns is
// "--namespace=", which scopes to nothing — or, depending on the tool, to
// everything. A pattern written with * admits "" without its author noticing,
// so the rule lives here rather than in each author's regular expression.
func TestEmptyParameterIsRefused(t *testing.T) {
	h := Handler{Name: Capability, Commands: []Command{{
		Name: "list", Path: "/bin/echo", Args: []string{"--namespace={ns}"},
		Params: map[string]Param{"ns": {Pattern: regexp.MustCompile(`\A(?:[a-z0-9-]*)\z`), Source: "[a-z0-9-]*"}},
	}}}
	args, _ := json.Marshal(Request{Operation: "list", Params: map[string]string{"ns": ""}})
	result, err := h.DispatchCall(context.Background(), sys.Syscall{Name: Capability, Args: args}, sys.Authorization{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status() != sys.StatusFailed || result.Errno() != sys.ErrnoInvalidArgs {
		t.Fatalf("got %v/%v, want failed/invalid_args — an empty value reached the argument",
			result.Status(), result.Errno())
	}
}
