package internet_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/internet"
)

func TestAllowedGETSucceeds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := loopbackClient(mustPolicy(t, "GET:"+server.URL))
	response, err := client.Do(context.Background(), internet.Request{Method: "GET", URL: server.URL})
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if response.Status != http.StatusOK || response.Body != "ok" {
		t.Fatalf("response = %+v", response)
	}
	if response.Headers["Content-Type"] != "text/plain" {
		t.Fatalf("headers = %+v, want the Content-Type surfaced", response.Headers)
	}
}

// A grant that allowlists POST can write: the request body reaches the server
// and the response comes back.
func TestAllowedPOSTSendsBody(t *testing.T) {
	var seen struct {
		method      string
		body        string
		contentType string
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.method = r.Method
		seen.contentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		seen.body = string(body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"created":true}`))
	}))
	defer server.Close()

	client := loopbackClient(mustPolicy(t, "POST:"+server.URL))
	response, err := client.Do(context.Background(), internet.Request{
		Method:  "POST",
		URL:     server.URL,
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    `{"hello":"world"}`,
	})
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if seen.method != "POST" || seen.body != `{"hello":"world"}` || seen.contentType != "application/json" {
		t.Fatalf("server saw %+v", seen)
	}
	if response.Status != http.StatusCreated || response.Body != `{"created":true}` {
		t.Fatalf("response = %+v", response)
	}
}

func TestDisallowedDomainFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("request should not reach disallowed server")
	}))
	defer server.Close()

	client := loopbackClient(mustPolicy(t, "GET:https://example.com"))
	_, err := client.Do(context.Background(), internet.Request{Method: "GET", URL: server.URL})
	if err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("error = %v, want not-allowlisted", err)
	}
}

// A method outside the grant's allowlist is refused even when the host is
// allowed.
func TestDisallowedMethodFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("request should not reach server")
	}))
	defer server.Close()

	client := loopbackClient(mustPolicy(t, "GET:"+server.URL))
	_, err := client.Do(context.Background(), internet.Request{Method: "DELETE", URL: server.URL})
	if err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("error = %v, want not-allowlisted", err)
	}
}

// The method wildcard "*" lets a grant permit every method against a host.
func TestMethodWildcardAllowsAnyMethod(t *testing.T) {
	policy := mustPolicy(t, "*:https://api.example.com")
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		if err := policy.Allows(method, "https://api.example.com/x"); err != nil {
			t.Fatalf("method %s: %v", method, err)
		}
	}
	if err := policy.Allows("GET", "https://other.example.com"); err == nil {
		t.Fatal("wildcard method must still pin the host")
	}
}

func TestHostWildcardPinsMethod(t *testing.T) {
	policy := mustPolicy(t, "GET:*")
	for _, target := range []string{"https://example.com/path", "http://localhost:8080/value"} {
		if err := policy.Allows(http.MethodGet, target); err != nil {
			t.Fatalf("allow %s: %v", target, err)
		}
	}
	if err := policy.Allows(http.MethodPost, "https://example.com"); err == nil {
		t.Fatal("host wildcard must still pin the method")
	}
}

func TestNonHTTPSchemeFails(t *testing.T) {
	client := loopbackClient(mustPolicy(t, "GET:https://example.com"))
	_, err := client.Do(context.Background(), internet.Request{Method: "GET", URL: "file:///tmp/data.txt"})
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("error = %v, want scheme-not-allowed", err)
	}
}

func TestRedirectToDisallowedDomainFails(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("redirect target should not be reached")
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()

	client := loopbackClient(mustPolicy(t, "GET:"+source.URL))
	_, err := client.Do(context.Background(), internet.Request{Method: "GET", URL: source.URL})
	if err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("error = %v, want not-allowlisted", err)
	}
}

func TestResponseBodyIsByteLimited(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("abcdef"))
	}))
	defer server.Close()

	client := loopbackClient(mustPolicy(t, "GET:"+server.URL))
	client.MaxBytes = 3
	response, err := client.Do(context.Background(), internet.Request{Method: "GET", URL: server.URL})
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if response.Body != "abc" {
		t.Fatalf("body = %q, want abc", response.Body)
	}
}

func TestRequestBodyIsByteLimited(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("oversized request should not be sent")
	}))
	defer server.Close()

	client := loopbackClient(mustPolicy(t, "POST:"+server.URL))
	client.MaxRequestBytes = 4
	_, err := client.Do(context.Background(), internet.Request{Method: "POST", URL: server.URL, Body: "toolong"})
	if err == nil || !strings.Contains(err.Error(), "request body exceeds") {
		t.Fatalf("error = %v, want request-body-exceeds", err)
	}
}

// A host-held credential bound to one origin must not ride a redirect to a
// different origin — even one the policy allowlists — because Go's stdlib
// strips only Authorization/Cookie, forwarding a custom header (X-Api-Key) that
// would otherwise reach an attacker-controlled host.
func TestInjectedCredentialStrippedOnCrossOriginRedirect(t *testing.T) {
	var targetSaw string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetSaw = r.Header.Get("X-Api-Key")
		_, _ = w.Write([]byte("done"))
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()

	// Both origins allowlisted — the exfil precondition (the redirect passes the
	// policy re-check), so only header stripping stands between the credential
	// and the other host.
	client := loopbackClient(mustPolicy(t, "GET:"+source.URL+",GET:"+target.URL))
	ctx := internet.WithInjectedCredential(context.Background(), internet.OriginOf(mustURL(t, source.URL)), []string{"X-Api-Key"})
	if _, err := client.Do(ctx, internet.Request{Method: "GET", URL: source.URL, Headers: map[string]string{"X-Api-Key": "SECRET"}}); err != nil {
		t.Fatalf("do: %v", err)
	}
	if targetSaw != "" {
		t.Fatalf("cross-origin redirect leaked the credential: target saw X-Api-Key=%q", targetSaw)
	}
}

// A same-origin redirect (path change on the bound host) keeps the credential —
// stripping is scoped to origin changes, not every hop.
func TestInjectedCredentialSurvivesSameOriginRedirect(t *testing.T) {
	var saw string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/b" {
			http.Redirect(w, r, "/b", http.StatusFound)
			return
		}
		saw = r.Header.Get("X-Api-Key")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := loopbackClient(mustPolicy(t, "GET:"+server.URL))
	ctx := internet.WithInjectedCredential(context.Background(), internet.OriginOf(mustURL(t, server.URL)), []string{"X-Api-Key"})
	if _, err := client.Do(ctx, internet.Request{Method: "GET", URL: server.URL + "/a", Headers: map[string]string{"X-Api-Key": "SECRET"}}); err != nil {
		t.Fatalf("do: %v", err)
	}
	if saw != "SECRET" {
		t.Fatalf("same-origin redirect dropped the credential: saw %q", saw)
	}
}

// A custom CheckRedirect disables net/http's built-in 10-hop ceiling, so the
// client must re-impose one or a hostile server loops it until timeout.
func TestRedirectCountIsCapped(t *testing.T) {
	var hops int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hops, 1)
		http.Redirect(w, r, r.URL.String(), http.StatusFound)
	}))
	defer server.Close()

	client := loopbackClient(mustPolicy(t, "GET:"+server.URL))
	_, err := client.Do(context.Background(), internet.Request{Method: "GET", URL: server.URL})
	if err == nil || !strings.Contains(err.Error(), "stopped after") {
		t.Fatalf("error = %v, want the redirect cap", err)
	}
	if got := atomic.LoadInt32(&hops); got > internet.DefaultMaxRedirects+1 {
		t.Fatalf("server hit %d times, want capped near %d", got, internet.DefaultMaxRedirects)
	}
}

// RFC 6598 carrier-grade NAT (100.64.0.0/10) is not covered by net.IP.IsPrivate
// but clouds route internal services there — the dial guard must block it.
func TestGuardDialAddressBlocksCGNAT(t *testing.T) {
	if err := internet.GuardDialAddress("100.64.0.1:443"); err == nil {
		t.Fatal("100.64.0.0/10 (CGNAT) should be refused as non-public")
	}
	if err := internet.GuardDialAddress("100.127.255.255:443"); err == nil {
		t.Fatal("100.127.255.255 (top of CGNAT) should be refused")
	}
	if err := internet.GuardDialAddress("8.8.8.8:443"); err != nil {
		t.Fatalf("a public IP must still dial: %v", err)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	return u
}

func mustPolicy(t *testing.T, raw string) internet.Policy {
	t.Helper()
	policy, err := internet.ParseAllowlist(raw)
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	return policy
}

// loopbackClient allows private-network dials because these tests serve from
// httptest (127.0.0.1). Production blocks them unless a grant opts in — see
// TestBlocksPrivateNetworkByDefault.
func loopbackClient(policy internet.Policy) *internet.Client {
	c := internet.NewClient(policy)
	c.AllowPrivateNetwork = true
	return c
}

// The SSRF guard: allowlisting a name does not authorize reaching a non-public
// address it resolves to. By default a connection whose resolved IP is
// loopback/private/link-local (the 169.254.169.254 metadata endpoint, a
// localhost admin port, an RFC 1918 host) is refused at dial time, so a
// public-looking grant cannot be turned into internal access.
func TestBlocksPrivateNetworkByDefault(t *testing.T) {
	var reached bool
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))
	defer server.Close()

	// The server is on 127.0.0.1; the policy allowlists exactly it, yet the
	// default guard must still refuse the dial.
	client := internet.NewClient(mustPolicy(t, "GET:"+server.URL))
	_, err := client.Do(context.Background(), internet.Request{Method: "GET", URL: server.URL})
	if err == nil {
		t.Fatal("a loopback request succeeded with the SSRF guard on")
	}
	if reached {
		t.Fatal("SECURITY: the request reached a private-network server despite the guard")
	}
	if !strings.Contains(err.Error(), "non-public") && !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("error = %v, want a blocked/non-public dial error", err)
	}
}

func TestAllowPrivateNetworkOptIn(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("internal"))
	}))
	defer server.Close()

	// The explicit opt-in is what a grant meant to reach an internal service sets.
	client := internet.NewClient(mustPolicy(t, "GET:"+server.URL))
	client.AllowPrivateNetwork = true
	response, err := client.Do(context.Background(), internet.Request{Method: "GET", URL: server.URL})
	if err != nil {
		t.Fatalf("opt-in private request failed: %v", err)
	}
	if response.Body != "internal" {
		t.Fatalf("body = %q, want internal", response.Body)
	}
}
