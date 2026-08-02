// Package command runs one host command from an author-declared allowlist.
//
// This is the most dangerous shape a capability can take, so the split of
// authority is deliberate and absolute: the host owns the whole command line,
// and the guest owns nothing but the values of named parameter slots. A guest
// never supplies a path, an argument vector, a working directory, or an
// environment variable — it names one allowlisted command and fills in the slots
// that command declared.
//
// Three properties do the work:
//
//   - No shell, ever. The command is executed directly with its argument vector
//     (exec, not `sh -c`), so shell metacharacters in a parameter are not
//     escaped or filtered — there is nothing to interpret them. Injection is not
//     blocked here; it is absent. A guest that wants a script gets one because
//     the *author* allowlisted `/bin/sh /opt/…/script.sh` as the fixed argv.
//
//   - Every slot is a closed set or an anchored pattern. A parameter is declared
//     either as an explicit list of permitted values or as a regular expression
//     that the loader anchors, so a pattern cannot silently match more than its
//     author read it as matching.
//
//   - No parameter may contain a control character, and none may begin with
//     "-". A value that lands where the program
//     expects an operand but starts with a dash becomes a flag, and flags are
//     where read-only tools stop being read-only (`kubectl get -o
//     go-template=…`, `git -c core.sshCommand=…`). An author who wants a flag
//     writes it into the template.
//
// The environment is never inherited: a child sees exactly the variables its
// command declared and nothing else, so the host's own secrets, PATH, and
// loader settings are not ambient authority the guest can reach through.
package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/aurora-capcompute/capcompute/sys"
)

// Capability is the name a core.command grant publishes. run is the only
// operation (the ADT discriminator inside the call args).
const Capability = "core.command"

// VerbRun names the one operation this driver implements.
const VerbRun = "run"

const (
	// DefaultTimeout bounds one command's wall-clock run.
	DefaultTimeout = 30 * time.Second
	// DefaultMaxOutputBytes bounds each of stdout and stderr.
	DefaultMaxOutputBytes = 64 * 1024
)

// Request is one command a program asks the host to run: the allowlisted
// command's name, plus a value for each slot that command declared.
type Request struct {
	Operation string            `json:"operation"`
	Name      string            `json:"name"`
	Params    map[string]string `json:"params,omitempty"`
}

// Response is what the program observes: the exit status and the bounded
// output. Output is captured, never streamed — a command that writes more than
// its bound is truncated and says so rather than filling the context window.
type Response struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	// Truncated reports that output passed the byte bound and was cut.
	Truncated bool `json:"truncated,omitempty"`
}

// Param is one declared slot. Exactly one of OneOf and Pattern is set: a closed
// set of permitted values, or an anchored regular expression. A closed set is
// the better answer whenever the author can enumerate the choices — it says what
// the policy actually is, it cannot over-match, and it is published to the guest
// as a JSON Schema enum, so the kernel Validator refuses a bad value before this
// driver ever runs.
type Param struct {
	OneOf   []string
	Pattern *regexp.Regexp
	// Source is the pattern as the author wrote it, for the published schema.
	Source string
}

// validate checks one guest-supplied value against the slot.
func (p Param) validate(name, value string) error {
	// A value that becomes a flag reaches authority the template never granted,
	// whatever else it matches. Checked before the set or the pattern, so no
	// author can accidentally admit one.
	if strings.HasPrefix(value, "-") {
		return fmt.Errorf("parameter %q may not begin with %q: it would be read as a flag, not a value", name, "-")
	}
	// No control characters. A value spanning lines corrupts the one thing a
	// human approving this call reads — the summary — and the audit record with
	// it, and no operand of a command-line tool needs one. Rejecting them here
	// also means an author's pattern need not think about it.
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("parameter %q contains a control character (%q)", name, r)
		}
	}
	if len(p.OneOf) > 0 {
		for _, allowed := range p.OneOf {
			if value == allowed {
				return nil
			}
		}
		return fmt.Errorf("parameter %q must be one of %s", name, strings.Join(p.OneOf, ", "))
	}
	if p.Pattern != nil && !p.Pattern.MatchString(value) {
		return fmt.Errorf("parameter %q does not match %s", name, p.Source)
	}
	return nil
}

// Command is one allowlisted invocation. Everything here is host-authored
// trusted policy: the guest contributes only the Params values.
type Command struct {
	// Name is what a guest calls this command by.
	Name string
	// Description is the author's one line about what it does, published to the
	// guest so the model can choose between commands.
	Description string
	// Path is the absolute executable. There is no PATH lookup: which binary
	// runs is host-side config, not an ambient property of the environment.
	Path string
	// Args is the argument vector, with {slot} placeholders substituted from the
	// request's params. A placeholder may be embedded in a larger argument
	// ("--ns={namespace}"); the result is still one argv element.
	Args []string
	// Dir is the working directory (absolute; empty means the host process's).
	Dir string
	// Env is the child's entire environment. It is never inherited: an empty Env
	// means an empty environment.
	Env map[string]string
	// Params declares the slots Args may reference.
	Params map[string]Param

	Timeout        time.Duration
	MaxOutputBytes int64

	RequireApproval bool
	Labels          []string
	Taints          []string
}

// ParamNames lists the declared slots in a stable order.
func (c Command) ParamNames() []string {
	names := make([]string, 0, len(c.Params))
	for name := range c.Params {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Handler adapts the allowlist to the builtin dispatcher, enforcing the command
// allowlist, its slot declarations, flow policy, and approval before anything is
// executed.
type Handler struct {
	Name     string
	Commands []Command
	// run executes a resolved command. It is a field so tests can observe what
	// would run without spawning it; production leaves it nil and gets execCommand.
	run func(ctx context.Context, c Command, argv []string) (Response, error)
}

func (h Handler) Handles(name string) bool { return name == h.Name }

// DispatchCall validates a run against the allowlist and its slot declarations,
// gates it on flow policy and approval, executes it, and stamps the result's
// provenance.
func (h Handler) DispatchCall(ctx context.Context, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	var request Request
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", h.Name, err)), nil
	}
	if request.Operation != VerbRun {
		if request.Operation == "" {
			return sys.FailCode(sys.ErrnoInvalidArgs, "operation is required"), nil
		}
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("unknown operation %q (only %s is supported)", request.Operation, VerbRun)), nil
	}
	command, ok := h.lookup(request.Name)
	if !ok {
		return sys.FailCode(sys.ErrnoDenied, fmt.Sprintf(
			"command %q is not granted (granted: %s)", request.Name, strings.Join(h.names(), ", "))), nil
	}

	argv, err := resolve(command, request.Params)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
	}

	// Sink guard: refuse before running if the run has observed a label this
	// command forbids — a command is an effect, and this is where tainted data is
	// barred from steering one.
	if blocked := sys.BlockedBy(sys.Taint(ctx), command.Taints); len(blocked) > 0 {
		return sys.FailCode(sys.ErrnoDenied, fmt.Sprintf(
			"flow policy: this run has observed %v, which may not flow into %q", blocked, command.Name)), nil
	}

	summary := summarize(command, request.Params)
	if command.RequireApproval && auth.Decision != sys.Approved {
		return sys.Yield("Approve " + summary), nil
	}

	runner := h.run
	if runner == nil {
		runner = execCommand
	}
	response, err := runner(ctx, command, argv)
	if err != nil {
		if ctx.Err() != nil {
			return sys.SyscallResult{}, ctx.Err()
		}
		// A command that could not be started at all — a missing binary, a bad
		// working directory. The run still touched a labeled capability, so the
		// failure carries its labels: an error channel must not launder them.
		return sys.FailCode(sys.ErrnoInternal, fmt.Sprintf("%s: %v", summary, err)).WithLabels(command.Labels...), nil
	}
	if response.ExitCode != 0 {
		// A non-zero exit is the command's own verdict, not an infrastructure
		// failure. Surface it as a failure the model can read and react to, with
		// the command's own stderr as the message.
		return sys.FailCode(sys.ErrnoInvalidArgs, failureMessage(summary, response)).WithLabels(command.Labels...), nil
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return sys.FailCode(sys.ErrnoInternal, fmt.Sprintf("encode run result: %v", err)), nil
	}
	return sys.Result(encoded).WithLabels(command.Labels...), nil
}

func (h Handler) lookup(name string) (Command, bool) {
	for _, command := range h.Commands {
		if command.Name == name {
			return command, true
		}
	}
	return Command{}, false
}

func (h Handler) names() []string {
	out := make([]string, 0, len(h.Commands))
	for _, command := range h.Commands {
		out = append(out, command.Name)
	}
	sort.Strings(out)
	return out
}

// placeholder matches a {slot} reference in an argument template.
var placeholder = regexp.MustCompile(`\{([a-z][a-z0-9_]*)\}`)

// resolve validates every supplied parameter against its declaration and
// substitutes them into the command's argument vector. Every declared slot must
// be supplied and no undeclared one may be: a template with an unfilled slot
// would otherwise run with a literal "{name}" argument.
func resolve(command Command, params map[string]string) ([]string, error) {
	for name := range params {
		if _, declared := command.Params[name]; !declared {
			return nil, fmt.Errorf("command %q takes no parameter %q (takes: %s)",
				command.Name, name, strings.Join(command.ParamNames(), ", "))
		}
	}
	for _, name := range command.ParamNames() {
		value, supplied := params[name]
		if !supplied {
			return nil, fmt.Errorf("command %q requires parameter %q", command.Name, name)
		}
		if err := command.Params[name].validate(name, value); err != nil {
			return nil, err
		}
	}
	argv := make([]string, 0, len(command.Args))
	for _, arg := range command.Args {
		argv = append(argv, placeholder.ReplaceAllStringFunc(arg, func(match string) string {
			return params[placeholder.FindStringSubmatch(match)[1]]
		}))
	}
	return argv, nil
}

// execCommand runs the resolved command with a bounded lifetime, a bounded
// output, and its own process group, and reports how it ended.
func execCommand(ctx context.Context, command Command, argv []string) (Response, error) {
	timeout := command.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	maxBytes := command.MaxOutputBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxOutputBytes
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, command.Path, argv...)
	cmd.Dir = command.Dir
	// The child's whole environment, never inherited. A nil Env would hand it
	// the host's, so an empty declaration must still produce an empty slice.
	env := make([]string, 0, len(command.Env))
	for key, value := range command.Env {
		env = append(env, key+"="+value)
	}
	sort.Strings(env)
	cmd.Env = env

	// Its own process group, so cancellation reaches the whole tree. Killing only
	// the direct child would orphan whatever it spawned — a shell script's
	// children would keep running, and holding the output pipe open would keep
	// this call blocked past its deadline.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	// A process that ignores the kill must not hold the quantum forever: after
	// this grace period Wait returns regardless.
	cmd.WaitDelay = 2 * time.Second

	stdout := &boundedBuffer{limit: maxBytes}
	stderr := &boundedBuffer{limit: maxBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	response := Response{
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		Truncated: stdout.truncated || stderr.truncated,
	}
	switch {
	case err == nil:
		response.ExitCode = 0
	case errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil:
		return Response{}, fmt.Errorf("timed out after %s", timeout)
	default:
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			response.ExitCode = exitErr.ExitCode()
			break
		}
		// Could not start at all: no such binary, bad working directory.
		return Response{}, err
	}
	return response, nil
}

// boundedBuffer accumulates up to limit bytes and discards the rest, recording
// that it did. It never grows past the bound however much the child writes.
type boundedBuffer struct {
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - int64(b.buf.Len())
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil // absorbed and dropped; the writer must not see a short write
	}
	if int64(len(p)) > remaining {
		b.buf.Write(p[:remaining])
		b.truncated = true
		return len(p), nil
	}
	b.buf.Write(p)
	return len(p), nil
}

func (b *boundedBuffer) String() string { return b.buf.String() }

// summarize renders a command and its arguments for an approval prompt and for
// error messages.
func summarize(command Command, params map[string]string) string {
	var b strings.Builder
	b.WriteString("command ")
	b.WriteString(command.Name)
	names := command.ParamNames()
	if len(names) == 0 {
		return b.String()
	}
	b.WriteString(" (")
	for i, name := range names {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s=%s", name, params[name])
	}
	b.WriteString(")")
	return b.String()
}

// failureMessage renders a non-zero exit for the model: the command's own
// stderr where it wrote one, its stdout otherwise.
func failureMessage(summary string, response Response) string {
	detail := strings.TrimSpace(response.Stderr)
	if detail == "" {
		detail = strings.TrimSpace(response.Stdout)
	}
	if detail == "" {
		return fmt.Sprintf("%s: exited %d", summary, response.ExitCode)
	}
	return fmt.Sprintf("%s: exited %d: %s", summary, response.ExitCode, detail)
}
