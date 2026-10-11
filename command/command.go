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
	"maps"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aurora-capcompute/capcompute/sys"
)

// Capability is the name a core.command grant publishes. Each allowlisted
// command is one operation of it, named by the `operation` field in the args.
const Capability = "core.command"

const (
	// DefaultTimeout bounds one command's wall-clock run.
	DefaultTimeout = 30 * time.Second
	// DefaultMaxOutputBytes bounds each of stdout and stderr.
	DefaultMaxOutputBytes = 64 * 1024
)

// Request is one command a program asks the host to run: the operation names
// the allowlisted command, and Params carries a value for each slot it declared.
type Request struct {
	Operation string            `json:"operation"`
	Params    map[string]string `json:"params,omitempty"`
}

// Response is what the program observes: the exit status and the bounded
// output. Output is captured, never streamed — a command that writes more than
// its bound is truncated and says so rather than filling the context window.
// A non-zero exit is the command's own verdict, so it is a result like any
// other, and the program decides what it means.
type Response struct {
	// ExitCode is -1 when a signal ended the command.
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
	// Exclude, beside a pattern, refuses values the pattern admits. It is
	// anchored like the pattern. ExcludeSource is the author's text.
	Exclude       *regexp.Regexp
	ExcludeSource string
}

// validate checks one guest-supplied value against the slot.
func (p Param) validate(name, value string) error {
	// A value that becomes a flag reaches authority the template never granted,
	// whatever else it matches. Checked before the set or the pattern, so no
	// author can accidentally admit one.
	if strings.HasPrefix(value, "-") {
		return fmt.Errorf("parameter %q may not begin with %q: it would be read as a flag, not a value", name, "-")
	}
	// An empty value is an empty argv element, which a template embeds as
	// "--namespace=" — a narrowing flag that has silently become no restriction
	// at all. It is available only by enumerating "" among the permitted values;
	// a pattern that happens to match it does not count, and is refused where it
	// is written.
	if value == "" && !slices.Contains(p.OneOf, "") {
		return fmt.Errorf("parameter %q is empty: an empty argument must be an enumerated value", name)
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
		if slices.Contains(p.OneOf, value) {
			return nil
		}
		return fmt.Errorf("parameter %q must be one of %s", name, strings.Join(p.OneOf, ", "))
	}
	if p.Pattern != nil && !p.Pattern.MatchString(value) {
		return fmt.Errorf("parameter %q does not match %s", name, p.Source)
	}
	if p.Exclude != nil && p.Exclude.MatchString(value) {
		return fmt.Errorf("parameter %q may not match %s", name, p.ExcludeSource)
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
	// Dir is the working directory (absolute). The manifest states it: a
	// command never runs in the host process's own working directory.
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
	return slices.Sorted(maps.Keys(c.Params))
}

// DispatchCall runs the command: it checks the guest's values against the
// slot declarations, executes the command, and reports how it ended. The
// grant table routed the call here, so the command is the one the call named.
func (command Command) DispatchCall(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error) {
	var request Request
	if err := json.Unmarshal(call.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode %s request: %v", call.Name, err)), nil
	}

	argv, err := resolve(command, request.Params)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
	}

	// Flow policy and approval are this command's entry's, enforced by the
	// runtime above and below the replay tape. This handler runs the effect.
	response, err := execCommand(ctx, command, argv)
	if err == nil {
		encoded, err := json.Marshal(response)
		if err != nil {
			return sys.SyscallResult{}, err
		}
		return sys.Result(encoded), nil
	}
	if ctx.Err() != nil {
		return sys.SyscallResult{}, ctx.Err()
	}
	// A timeout may well pass on a retry — a slow cluster, a busy host — while
	// a command that could not start at all (missing binary, bad working
	// directory) is a configuration fault that retrying will not fix.
	errno := sys.ErrnoInternal
	var timedOut errTimeout
	if errors.As(err, &timedOut) {
		errno = sys.ErrnoTransient
	}
	return sys.FailCode(errno, fmt.Sprintf("%s: %v", summarize(command, request.Params), err)), nil
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
	return substitute(command.Args, params), nil
}

// substitute fills each {slot} in an argument template from params.
func substitute(args []string, params map[string]string) []string {
	argv := make([]string, 0, len(args))
	for _, arg := range args {
		argv = append(argv, placeholder.ReplaceAllStringFunc(arg, func(match string) string {
			return params[placeholder.FindStringSubmatch(match)[1]]
		}))
	}
	return argv
}

// prompt shows the human approving a call what will run: the executable and
// its exact arguments, each quoted, the working directory, and the names —
// never the values — of the environment it gets.
func (c Command) prompt(call sys.Syscall) string {
	// The Validator admitted these arguments against this command's schema.
	var request Request
	_ = json.Unmarshal(call.Args, &request)
	quoted := []string{strconv.Quote(c.Path)}
	for _, arg := range substitute(c.Args, request.Params) {
		quoted = append(quoted, strconv.Quote(arg))
	}
	prompt := fmt.Sprintf("run: %s\ndir: %s", strings.Join(quoted, " "), c.Dir)
	if len(c.Env) > 0 {
		prompt += "\nenv: " + strings.Join(slices.Sorted(maps.Keys(c.Env)), ", ")
	}
	return prompt
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

	// A floor enforced where the command runs, not only where it was configured:
	// a relative path would be resolved against the working directory or PATH,
	// which is exactly the ambient authority this driver refuses to depend on.
	// The registry checks this too; a Command built by hand must not slip past it.
	if !filepath.IsAbs(command.Path) {
		return Response{}, fmt.Errorf("executable %q is not an absolute path", command.Path)
	}

	cmd := exec.CommandContext(ctx, command.Path, argv...)
	cmd.Dir = command.Dir
	// The child's whole environment, never inherited. A nil Env would hand it
	// the host's, so an empty declaration must still produce an empty slice.
	env := make([]string, 0, len(command.Env))
	for key, value := range command.Env {
		env = append(env, key+"="+value)
	}
	slices.Sort(env)
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
	switch {
	case err != nil && ctx.Err() != nil:
		return Response{}, errTimeout{after: timeout}
	case cmd.ProcessState == nil:
		// Could not start at all: no such binary, bad working directory.
		return Response{}, err
	}
	// The command ran, and its exit status stands — also when a child it left
	// behind held the output open past WaitDelay (exec.ErrWaitDelay).
	return Response{
		ExitCode:  cmd.ProcessState.ExitCode(),
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		Truncated: stdout.truncated || stderr.truncated,
	}, nil
}

// errTimeout is a command stopped by its own deadline, as opposed to one that
// never started.
type errTimeout struct{ after time.Duration }

func (e errTimeout) Error() string { return fmt.Sprintf("timed out after %s", e.after) }

// boundedBuffer accumulates up to limit bytes and discards the rest, recording
// that it did. It never grows past the bound however much the child writes.
type boundedBuffer struct {
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

// Write keeps what fits and drops the rest. It reports the whole write as done:
// the writer must not see a short write.
func (b *boundedBuffer) Write(p []byte) (int, error) {
	keep := min(int64(len(p)), b.limit-int64(b.buf.Len()))
	b.buf.Write(p[:keep])
	b.truncated = b.truncated || keep < int64(len(p))
	return len(p), nil
}

func (b *boundedBuffer) String() string { return b.buf.String() }

// summarize renders a command and its arguments for an error message.
func summarize(command Command, params map[string]string) string {
	names := command.ParamNames()
	if len(names) == 0 {
		return "command " + command.Name
	}
	pairs := make([]string, 0, len(names))
	for _, name := range names {
		pairs = append(pairs, name+"="+params[name])
	}
	return fmt.Sprintf("command %s (%s)", command.Name, strings.Join(pairs, ", "))
}
