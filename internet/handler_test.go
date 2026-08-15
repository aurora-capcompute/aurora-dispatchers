package internet_test

import (
	"context"
	"encoding/json"
	"testing"

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

func newInternetHandler(client internet.Doer) internet.Handler {
	return internet.Handler{
		Name:   "core.internet",
		Client: client,
	}
}

func internetCall(method, url string) sys.Syscall {
	args, _ := json.Marshal(internet.Request{Method: method, URL: url})
	return sys.Syscall{Abi: sys.ABIVersion, Name: "core.internet", Args: args}
}

// Flow policy and approval used to be enforced here and are now the method's
// entry's — the sink guard in the runtime's monitor, approval in builtin's
// dispatcher. They are tested there; this package tests the request.

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
