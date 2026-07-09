package builtin_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/internet"
	"github.com/aurora-capcompute/capcompute/sys"
)

// recordingClient captures the request that actually reached the network, so a
// test can assert on the headers the host attached (or refused to).
type recordingClient struct {
	seen     internet.Request
	response internet.Response
}

func (c *recordingClient) Do(_ context.Context, req internet.Request) (internet.Response, error) {
	c.seen = req
	return c.response, nil
}

// internetCallWithHeaders builds a call carrying guest-supplied headers — used
// to prove the guest cannot preempt or read a host-injected credential.
func internetCallWithHeaders(method, url string, headers map[string]string) sys.Syscall {
	args, _ := json.Marshal(internet.Request{Method: method, URL: url, Headers: headers})
	return sys.Syscall{Abi: sys.ABIVersion, Name: "core.internet", Args: args}
}

func injectingHandler(client builtin.InternetClient) builtin.InternetHandler {
	return builtin.InternetHandler{
		Name:    "core.internet",
		Methods: map[string]builtin.InternetMethodPolicy{"*": {}},
		Client:  client,
		Injections: []builtin.CredentialInjection{{
			Methods: []string{"*"},
			Host:    "onyx.example.com",
			Headers: map[string]string{"Authorization": "Bearer tok-abc"},
			Labels:  []string{"credential:ONYX_TOKEN@abc123def456"},
		}},
	}
}

// The host-held credential reaches the matching request even though the guest
// never named it, and the provenance label is stamped on the result — but the
// value never is.
func TestInjectAttachesCredentialAndLabels(t *testing.T) {
	client := &recordingClient{response: internet.Response{Status: 200, Body: "ok"}}
	handler := injectingHandler(client)

	result, err := handler.DispatchCall(context.Background(), internetCall("GET", "https://onyx.example.com/v1/data"), sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if got := client.seen.Headers["Authorization"]; got != "Bearer tok-abc" {
		t.Fatalf("Authorization reaching network = %q, want %q", got, "Bearer tok-abc")
	}
	if !slices.Contains(result.Labels(), "credential:ONYX_TOKEN@abc123def456") {
		t.Fatalf("labels = %v, want the credential provenance stamped", result.Labels())
	}
	for _, label := range result.Labels() {
		if label == "Bearer tok-abc" {
			t.Fatal("SECURITY: the token value appeared in the result labels")
		}
	}
}

// The host header wins over a guest-supplied header of the same name: the guest
// can neither read nor override the injected credential.
func TestInjectHostWinsOverGuestHeader(t *testing.T) {
	client := &recordingClient{response: internet.Response{Status: 200}}
	handler := injectingHandler(client)

	// A guest-supplied Authorization it is trying to spoof must lose to the host.
	call := internetCallWithHeaders("POST", "https://onyx.example.com/v1/data", map[string]string{"Authorization": "Bearer guest-forged"})
	if _, err := handler.DispatchCall(context.Background(), call, sys.Authorization{}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if got := client.seen.Headers["Authorization"]; got != "Bearer tok-abc" {
		t.Fatalf("Authorization = %q, want the host value to win over the guest's forgery", got)
	}
}

// Host-wins holds even when the guest supplies the header under a different
// casing: the credential must not be left overridable by a lowercase alias.
func TestInjectHostWinsRegardlessOfGuestHeaderCasing(t *testing.T) {
	client := &recordingClient{response: internet.Response{Status: 200}}
	handler := injectingHandler(client)

	call := internetCallWithHeaders("GET", "https://onyx.example.com/v1/data",
		map[string]string{"authorization": "Bearer guest-forged"})
	if _, err := handler.DispatchCall(context.Background(), call, sys.Authorization{}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// Exactly one Authorization (any casing) reaches the wire, and it is the host's.
	var seen []string
	for name, value := range client.seen.Headers {
		if strings.EqualFold(name, "Authorization") {
			seen = append(seen, value)
		}
	}
	if len(seen) != 1 || seen[0] != "Bearer tok-abc" {
		t.Fatalf("Authorization headers reaching the wire = %v, want exactly [Bearer tok-abc]", seen)
	}
}

// An injection bound to onyx must not attach to any other host, even one the
// grant otherwise allows — the credential is scoped to its origin.
func TestInjectScopedToHost(t *testing.T) {
	client := &recordingClient{response: internet.Response{Status: 200}}
	handler := injectingHandler(client)

	result, err := handler.DispatchCall(context.Background(), internetCall("GET", "https://elsewhere.example.com/collect"), sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if _, ok := client.seen.Headers["Authorization"]; ok {
		t.Fatal("SECURITY: the credential leaked to a host it was not bound to")
	}
	if slices.Contains(result.Labels(), "credential:ONYX_TOKEN@abc123def456") {
		t.Fatal("a credential label was stamped for a request that carried no credential")
	}
}

// A method the injection does not list must not receive the credential, even on
// the bound host.
func TestInjectScopedToMethod(t *testing.T) {
	client := &recordingClient{response: internet.Response{Status: 200}}
	handler := builtin.InternetHandler{
		Name:    "core.internet",
		Methods: map[string]builtin.InternetMethodPolicy{"*": {}},
		Client:  client,
		Injections: []builtin.CredentialInjection{{
			Methods: []string{"GET"},
			Host:    "onyx.example.com",
			Headers: map[string]string{"Authorization": "Bearer tok-abc"},
			Labels:  []string{"credential:ONYX_TOKEN@abc123def456"},
		}},
	}
	if _, err := handler.DispatchCall(context.Background(), internetCall("POST", "https://onyx.example.com/v1/data"), sys.Authorization{}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if _, ok := client.seen.Headers["Authorization"]; ok {
		t.Fatal("SECURITY: the credential attached to a method it was not bound to")
	}
}
