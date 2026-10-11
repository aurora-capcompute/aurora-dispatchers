package command_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/monitor"
	"github.com/aurora-capcompute/aurora-dispatchers/command"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
	"github.com/aurora-capcompute/capcompute/sys"
)

// Any resource but secrets: the open set an operator wants for read access,
// which a closed set cannot list and a pattern alone cannot express. /bin/echo
// stands in for kubectl.
const anyResourceButSecrets = `{"capabilities":[{
  "operation":"get",
  "path":"/bin/echo",
  "dir":"/",
  "args":["get","{resource}"],
  "params":{"resource":{"pattern":"[A-Za-z0-9][A-Za-z0-9.-]*","exclude":"(?i)secrets?(\\..*)?"}},
  "require_approval":false
}]}`

func callGet(resource string) sys.Syscall {
	return sys.Syscall{Abi: sys.ABIVersion, Name: command.Capability,
		Args: json.RawMessage(`{"operation":"get","params":{"resource":"` + resource + `"}}`)}
}

func TestExcludeRefusesWhatThePatternAdmits(t *testing.T) {
	table := configure(t, anyResourceButSecrets)
	schema := string(table.Descriptors()[0].InputSchema)
	if !strings.Contains(schema, `"not"`) {
		t.Fatalf("the published schema does not carry the exclusion: %s", schema)
	}

	validated := monitor.NewValidator(table, sys.Dispatcher[string](capability.NewDispatcher[string](table)))
	routed := capability.NewDispatcher[string](table)
	for _, secret := range []string{"secrets", "secret", "Secret", "SECRETS", "secrets.v1", "secret.v1."} {
		// The Validator refuses it from the schema.
		result, err := validated.Dispatch(context.Background(), "p", callGet(secret), sys.Authorization{})
		if err != nil || result.Status() != sys.StatusFailed || result.Errno() != sys.ErrnoInvalidArgs {
			t.Fatalf("Validator admitted %q: %v %v", secret, result.Status(), err)
		}
		// The driver refuses it on its own, before anything runs.
		result, err = routed.Dispatch(context.Background(), "p", callGet(secret), sys.Authorization{})
		if err != nil || result.Status() != sys.StatusFailed || !strings.Contains(result.Message(), "may not match") {
			t.Fatalf("driver admitted %q: %v %s %v", secret, result.Status(), result.Message(), err)
		}
	}
	for _, resource := range []string{"pods", "configmaps", "nodes", "sealedsecrets.bitnami.com"} {
		result, err := validated.Dispatch(context.Background(), "p", callGet(resource), sys.Authorization{})
		if err != nil || result.Status() != sys.StatusResult {
			t.Fatalf("%q refused: %v %s %v", resource, result.Status(), result.Message(), err)
		}
	}
}

func TestExcludeConfigErrors(t *testing.T) {
	for name, params := range map[string]string{
		"unknown key":   `{"pattern":"[a-z]+","deny":"x"}`,
		"no pattern":    `{"exclude":"x"}`,
		"bad exclusion": `{"pattern":"[a-z]+","exclude":"("}`,
	} {
		grant := `{"capabilities":[{"operation":"get","path":"/bin/echo","dir":"/","args":["{resource}"],"params":{"resource":` + params + `}}]}`
		if _, err := (command.Registration{}).Configure(context.Background(), json.RawMessage(grant), registry.Services{}); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
}

// A command without slots admits a call with no params and one with an empty
// params object, and nothing else.
func TestCommandWithoutSlotsTakesEmptyParams(t *testing.T) {
	table := configure(t, `{"capabilities":[{"operation":"list","path":"/bin/echo","dir":"/","args":["ok"],"require_approval":false}]}`)
	validated := monitor.NewValidator(table, sys.Dispatcher[string](capability.NewDispatcher[string](table)))
	for args, want := range map[string]sys.SyscallStatus{
		`{"operation":"list"}`:                       sys.StatusResult,
		`{"operation":"list","params":{}}`:           sys.StatusResult,
		`{"operation":"list","params":{"x":"y"}}`:    sys.StatusFailed,
		`{"operation":"list","params":{},"extra":1}`: sys.StatusFailed,
	} {
		call := sys.Syscall{Abi: sys.ABIVersion, Name: command.Capability, Args: json.RawMessage(args)}
		result, err := validated.Dispatch(context.Background(), "p", call, sys.Authorization{})
		if err != nil || result.Status() != want {
			t.Errorf("%s: %v %s %v, want %v", args, result.Status(), result.Message(), err, want)
		}
	}
}
