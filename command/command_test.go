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
	result := dispatch(t, h, `{"operation":"run","name":"kubectl-get","params":{"context":"prod-eu","resource":"pods"}}`)
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
		args := `{"operation":"run","name":"kubectl-get","params":{"context":"` + context + `","resource":"pods"}}`
		if result := dispatch(t, h, args); result.Status() != sys.StatusResult {
			t.Fatalf("context %q must be admitted: %s", context, result.Message())
		}
	}
	for _, context := range []string{"prod", "prod-eu-evil", "not-prod-eu", "PROD-EU", "", "dev"} {
		args := `{"operation":"run","name":"kubectl-get","params":{"context":"` + context + `","resource":"pods"}}`
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
		args, _ := json.Marshal(Request{Operation: VerbRun, Name: "echo", Params: map[string]string{"value": value}})
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
		args, _ := json.Marshal(Request{Operation: VerbRun, Name: "echo", Params: map[string]string{"value": value}})
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
		args, _ := json.Marshal(Request{Operation: VerbRun, Name: "echo", Params: map[string]string{"value": value}})
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
		name string
		args string
	}{
		{"ungranted command", `{"operation":"run","name":"rm","params":{}}`},
		{"undeclared parameter", `{"operation":"run","name":"kubectl-get","params":{"context":"staging","resource":"pods","extra":"x"}}`},
		{"missing parameter", `{"operation":"run","name":"kubectl-get","params":{"context":"staging"}}`},
		{"unknown operation", `{"operation":"delete","name":"kubectl-get","params":{}}`},
		{"missing operation", `{"name":"kubectl-get","params":{}}`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if result := dispatch(t, h, test.args); result.Status() != sys.StatusFailed {
				t.Fatalf("expected a refusal, got %v", result.Status())
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
	result := dispatch(t, h, `{"operation":"run","name":"show-env","params":{}}`)
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
	result := dispatch(t, h, `{"operation":"run","name":"slow","params":{}}`)
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
	result := dispatch(t, h, `{"operation":"run","name":"flood","params":{}}`)
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
	result := dispatch(t, h, `{"operation":"run","name":"failing","params":{}}`)
	if result.Status() != sys.StatusFailed {
		t.Fatalf("a non-zero exit must fail, got %v", result.Status())
	}
	if !strings.Contains(result.Message(), "no such namespace") || !strings.Contains(result.Message(), "3") {
		t.Fatalf("the failure must carry the exit code and stderr: %q", result.Message())
	}
}

// A command marked for approval yields until it is approved, and nothing runs
// in the meantime.
func TestApprovalGate(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	script := filepath.Join(t.TempDir(), "touch.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o700); err != nil {
		t.Fatalf("write script: %v", err)
	}
	h := Handler{Name: Capability, Commands: []Command{{
		Name: "guarded", Path: "/bin/sh", Args: []string{script}, RequireApproval: true,
	}}}
	result, err := h.DispatchCall(context.Background(), sys.Syscall{
		Name: Capability,
		Args: json.RawMessage(`{"operation":"run","name":"guarded","params":{}}`),
	}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Status() != sys.StatusYield {
		t.Fatalf("an unapproved command must yield, got %v", result.Status())
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the command ran before it was approved")
	}
}

// A run whose taint the command forbids is refused before anything executes.
func TestFlowTaintBlocksTheRun(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	script := filepath.Join(t.TempDir(), "touch.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o700); err != nil {
		t.Fatalf("write script: %v", err)
	}
	h := Handler{Name: Capability, Commands: []Command{{
		Name: "guarded", Path: "/bin/sh", Args: []string{script}, Taints: []string{"untrusted_web"},
	}}}
	ctx := sys.WithTaint(context.Background(), []string{"untrusted_web"})
	result, err := h.DispatchCall(ctx, sys.Syscall{
		Name: Capability,
		Args: json.RawMessage(`{"operation":"run","name":"guarded","params":{}}`),
	}, sys.Authorization{Decision: sys.Approved})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Status() != sys.StatusFailed {
		t.Fatalf("a tainted run must be refused, got %v", result.Status())
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the command ran despite the flow policy")
	}
}
