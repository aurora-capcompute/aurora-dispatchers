package k8s

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aurora-capcompute/capcompute/sys"
)

// recordingServer is a fake API server that records the last request it saw and
// returns a canned status+body — enough to assert exactly what the driver sends.
type recordingServer struct {
	*httptest.Server
	mu         sync.Mutex
	method     string
	path       string
	query      string
	auth       string
	accept     string
	hits       int
	status     int
	body       string
	retryAfter string
}

func newRecordingServer() *recordingServer {
	rec := &recordingServer{status: 200, body: `{"kind":"PodList","apiVersion":"v1","items":[]}`}
	rec.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.method = r.Method
		rec.path = r.URL.Path
		rec.query = r.URL.RawQuery
		rec.auth = r.Header.Get("Authorization")
		rec.accept = r.Header.Get("Accept")
		rec.hits++
		status, body, retry := rec.status, rec.body, rec.retryAfter
		rec.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if retry != "" {
			w.Header().Set("Retry-After", retry)
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	return rec
}

func (r *recordingServer) snapshot() (method, path, query, auth, accept string, hits int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.method, r.path, r.query, r.auth, r.accept, r.hits
}

func newTestHandler(srv *recordingServer, resources []Permission) Handler {
	client := &Client{
		access:   Access{endpoint: srv.URL, tokens: staticToken("test-token")},
		http:     srv.Client(),
		limiter:  newRateLimiter(10_000, 10_000), // effectively unlimited for behavior tests
		timeout:  10 * time.Second,
		maxBytes: DefaultMaxResponseBytes,
	}
	return Handler{
		Name:            Capability,
		CredentialLabel: "credential:k8s-serviceaccount@abcdef012345",
		Client:          client,
		Resources:       resources,
	}
}

func fixtureResources() []Permission {
	return []Permission{
		{Group: "", Version: "v1", Resource: "pods", Verbs: map[string]bool{"get": true, "list": true},
			Namespaces: []string{"default", "kube-system"}, Labels: []string{"k8s"}},
		{Group: "", Version: "v1", Resource: "nodes", Verbs: map[string]bool{"get": true, "list": true},
			ClusterScoped: true},
		{Group: "apps", Version: "v1", Resource: "deployments", Verbs: map[string]bool{"get": true, "list": true},
			Namespaces: []string{"*"}},
		{Group: "", Version: "v1", Resource: "configmaps", Verbs: map[string]bool{"list": true},
			Namespaces: []string{"default"}, MetadataOnly: true},
	}
}

func dispatch(t *testing.T, h Handler, ctx context.Context, args string) sys.SyscallResult {
	t.Helper()
	res, err := h.DispatchCall(ctx, sys.Syscall{Abi: sys.ABIVersion, Name: Capability, Args: json.RawMessage(args)}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch error: %v", err)
	}
	return res
}

// Every operation the driver performs is a GET — the read-only guarantee. There
// is no code path that issues any other method, so the fake server must only
// ever see GET regardless of the operation.
func TestOnlyEverIssuesGET(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	h := newTestHandler(srv, fixtureResources())
	ctx := context.Background()

	calls := []string{
		`{"operation":"get","resource":"pods","namespace":"default","name":"web-0"}`,
		`{"operation":"list","resource":"pods","namespace":"default"}`,
		`{"operation":"get","resource":"nodes","name":"node-1"}`,
		`{"operation":"list","group":"apps","resource":"deployments","namespace":"default"}`,
	}
	for _, args := range calls {
		if r := dispatch(t, h, ctx, args); r.Status() != sys.StatusResult {
			t.Fatalf("%s => %v (%s)", args, r.Status(), r.Message())
		}
		if method, _, _, _, _, _ := srv.snapshot(); method != http.MethodGet {
			t.Fatalf("%s issued %s, want GET", args, method)
		}
	}
}

func TestGetPathAndCacheRead(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	srv.body = `{"kind":"Pod","metadata":{"name":"web-0"}}`
	h := newTestHandler(srv, fixtureResources())

	r := dispatch(t, h, context.Background(), `{"operation":"get","resource":"pods","namespace":"default","name":"web-0"}`)
	if r.Status() != sys.StatusResult {
		t.Fatalf("status = %v: %s", r.Status(), r.Message())
	}
	_, path, query, auth, accept, _ := srv.snapshot()
	if path != "/api/v1/namespaces/default/pods/web-0" {
		t.Fatalf("path = %q", path)
	}
	if !strings.Contains(query, "resourceVersion=0") {
		t.Fatalf("query %q lacks resourceVersion=0 (cache read)", query)
	}
	if auth != "Bearer test-token" {
		t.Fatalf("auth = %q, want the injected bearer token", auth)
	}
	if accept != "application/json" {
		t.Fatalf("accept = %q", accept)
	}
}

func TestNamedGroupAndClusterScopedPaths(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	h := newTestHandler(srv, fixtureResources())
	ctx := context.Background()

	dispatch(t, h, ctx, `{"operation":"get","group":"apps","resource":"deployments","namespace":"default","name":"web"}`)
	if _, path, _, _, _, _ := srv.snapshot(); path != "/apis/apps/v1/namespaces/default/deployments/web" {
		t.Fatalf("named-group path = %q", path)
	}

	dispatch(t, h, ctx, `{"operation":"get","resource":"nodes","name":"node-1"}`)
	if _, path, _, _, _, _ := srv.snapshot(); path != "/api/v1/nodes/node-1" {
		t.Fatalf("cluster-scoped path = %q", path)
	}
}

func TestListBoundsAndSelectors(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	h := newTestHandler(srv, fixtureResources())
	ctx := context.Background()

	// No limit given => the default page size; a server-side timeout is set.
	dispatch(t, h, ctx, `{"operation":"list","resource":"pods","namespace":"default"}`)
	_, _, query, _, _, _ := srv.snapshot()
	if !strings.Contains(query, "limit=50") {
		t.Fatalf("default list query %q lacks limit=50", query)
	}
	if !strings.Contains(query, "timeoutSeconds=") {
		t.Fatalf("list query %q lacks a server-side timeout", query)
	}

	// An over-max limit is clamped to the ceiling — a guest cannot ask for more.
	dispatch(t, h, ctx, `{"operation":"list","resource":"pods","namespace":"default","limit":100000}`)
	if _, _, query, _, _, _ := srv.snapshot(); !strings.Contains(query, "limit=500") {
		t.Fatalf("over-max limit not clamped: %q", query)
	}

	// Selectors pass through url-encoded.
	dispatch(t, h, ctx, `{"operation":"list","resource":"pods","namespace":"default","label_selector":"app=web","field_selector":"status.phase=Running"}`)
	_, _, query, _, _, _ = srv.snapshot()
	if !strings.Contains(query, "labelSelector=app%3Dweb") || !strings.Contains(query, "fieldSelector=status.phase%3DRunning") {
		t.Fatalf("selectors not encoded into query: %q", query)
	}
}

func TestContinueDropsResourceVersion(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	h := newTestHandler(srv, fixtureResources())
	dispatch(t, h, context.Background(), `{"operation":"list","resource":"pods","namespace":"default","continue":"eyJ2IjoxfQ"}`)
	_, _, query, _, _, _ := srv.snapshot()
	if strings.Contains(query, "resourceVersion=0") {
		t.Fatalf("continue paging must not also pin resourceVersion=0: %q", query)
	}
	if !strings.Contains(query, "continue=eyJ2IjoxfQ") {
		t.Fatalf("continue token missing: %q", query)
	}
}

func TestMetadataOnlyAcceptHeader(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	h := newTestHandler(srv, fixtureResources())
	ctx := context.Background()

	// The grant forces metadata-only on configmaps: the list asks for the
	// metadata list representation, so payload data never leaves the API server.
	dispatch(t, h, ctx, `{"operation":"list","resource":"configmaps","namespace":"default"}`)
	if _, _, _, _, accept, _ := srv.snapshot(); accept != "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1" {
		t.Fatalf("configmap list accept = %q, want metadata-list", accept)
	}

	// A request can tighten a full-object resource to metadata-only for a get.
	dispatch(t, h, ctx, `{"operation":"get","resource":"pods","namespace":"default","name":"web-0","metadata_only":true}`)
	if _, _, _, _, accept, _ := srv.snapshot(); accept != "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1" {
		t.Fatalf("metadata-only get accept = %q", accept)
	}
}

func TestAllowlistEnforcement(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	h := newTestHandler(srv, fixtureResources())
	ctx := context.Background()

	cases := []struct {
		name string
		args string
	}{
		{"ungranted resource", `{"operation":"get","resource":"secrets","namespace":"default","name":"db"}`},
		{"ungranted verb", `{"operation":"get","resource":"configmaps","namespace":"default","name":"cfg"}`},
		{"ungranted namespace", `{"operation":"get","resource":"pods","namespace":"prod","name":"web-0"}`},
		{"namespace on cluster-scoped", `{"operation":"get","resource":"nodes","namespace":"default","name":"node-1"}`},
		{"namespaced get without namespace", `{"operation":"get","resource":"pods","name":"web-0"}`},
		{"all-namespace list without wildcard grant", `{"operation":"list","resource":"pods"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := func() int { _, _, _, _, _, h := srv.snapshot(); return h }()
			r := dispatch(t, h, ctx, tc.args)
			if r.Status() != sys.StatusFailed {
				t.Fatalf("%s: status = %v, want failed", tc.name, r.Status())
			}
			if _, _, _, _, _, after := srv.snapshot(); after != before {
				t.Fatalf("%s: a denied request reached the API server", tc.name)
			}
		})
	}
}

// A wildcard-namespace grant may list across all namespaces (no namespace in the
// path), still bounded by the page limit.
func TestAllNamespaceListWhenWildcarded(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	h := newTestHandler(srv, fixtureResources())
	dispatch(t, h, context.Background(), `{"operation":"list","group":"apps","resource":"deployments"}`)
	_, path, query, _, _, _ := srv.snapshot()
	if path != "/apis/apps/v1/deployments" {
		t.Fatalf("all-namespace list path = %q", path)
	}
	if !strings.Contains(query, "limit=") {
		t.Fatalf("all-namespace list is unbounded: %q", query)
	}
}

// Guest-supplied identity fields that could inject a path or query are refused
// before any request is built.
func TestPathInjectionRejected(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	h := newTestHandler(srv, fixtureResources())
	ctx := context.Background()

	injections := []string{
		`{"operation":"get","resource":"pods","namespace":"default","name":"../../secrets/db"}`,
		`{"operation":"get","resource":"pods","namespace":"default/../kube-system","name":"web-0"}`,
		`{"operation":"get","resource":"pods","namespace":"default","name":"web-0?watch=true"}`,
		`{"operation":"list","resource":"po ds","namespace":"default"}`,
		`{"operation":"get","resource":"pods","namespace":"DEFAULT","name":"web"}`,
	}
	for _, args := range injections {
		before := func() int { _, _, _, _, _, h := srv.snapshot(); return h }()
		r := dispatch(t, h, ctx, args)
		if r.Status() != sys.StatusFailed || r.Errno() != sys.ErrnoInvalidArgs {
			t.Fatalf("%s => %v/%v, want failed/invalid_args", args, r.Status(), r.Errno())
		}
		if _, _, _, _, _, after := srv.snapshot(); after != before {
			t.Fatalf("%s reached the API server", args)
		}
	}
}

// A run that has observed a forbidden label may not steer a read: the sink guard
// refuses before the request.
func TestFlowTaintBlocksRead(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	resources := []Permission{{Group: "", Version: "v1", Resource: "pods",
		Verbs: map[string]bool{"get": true}, Namespaces: []string{"default"}, Taints: []string{"untrusted_web"}}}
	h := newTestHandler(srv, resources)

	tainted := sys.WithTaint(context.Background(), []string{"untrusted_web"})
	r := dispatch(t, h, tainted, `{"operation":"get","resource":"pods","namespace":"default","name":"web-0"}`)
	if r.Status() != sys.StatusFailed || r.Errno() != sys.ErrnoDenied {
		t.Fatalf("tainted read = %v/%v, want failed/denied", r.Status(), r.Errno())
	}
	if _, _, _, _, _, hits := srv.snapshot(); hits != 0 {
		t.Fatal("a flow-denied read reached the API server")
	}
}

func TestApprovalGate(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	resources := []Permission{{Group: "", Version: "v1", Resource: "pods",
		Verbs: map[string]bool{"get": true}, Namespaces: []string{"default"}, RequireApproval: true}}
	h := newTestHandler(srv, resources)
	args := `{"operation":"get","resource":"pods","namespace":"default","name":"web-0"}`

	// Unapproved yields for sign-off and does not touch the API server.
	if r := dispatch(t, h, context.Background(), args); r.Status() != sys.StatusYield {
		t.Fatalf("unapproved = %v, want yield", r.Status())
	}
	if _, _, _, _, _, hits := srv.snapshot(); hits != 0 {
		t.Fatal("an unapproved read reached the API server")
	}
	// Approved proceeds.
	res, err := h.DispatchCall(context.Background(),
		sys.Syscall{Abi: sys.ABIVersion, Name: Capability, Args: json.RawMessage(args)},
		sys.Authorization{Decision: sys.Approved})
	if err != nil || res.Status() != sys.StatusResult {
		t.Fatalf("approved = %v/%v (%s)", res.Status(), err, res.Message())
	}
}

func TestStatusCodeClassification(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	h := newTestHandler(srv, fixtureResources())
	args := `{"operation":"get","resource":"pods","namespace":"default","name":"web-0"}`

	cases := []struct {
		status int
		body   string
		want   sys.Errno
	}{
		{404, `{"kind":"Status","message":"pods \"web-0\" not found"}`, sys.ErrnoNotFound},
		{403, `{"kind":"Status","message":"forbidden"}`, sys.ErrnoDenied},
		{401, `{"kind":"Status","message":"unauthorized"}`, sys.ErrnoDenied},
		{500, `{"kind":"Status","message":"server error"}`, sys.ErrnoTransient},
		{429, `{"kind":"Status","message":"slow down"}`, sys.ErrnoTransient},
	}
	for _, tc := range cases {
		srv.mu.Lock()
		srv.status, srv.body = tc.status, tc.body
		srv.mu.Unlock()
		r := dispatch(t, h, context.Background(), args)
		if r.Status() != sys.StatusFailed || r.Errno() != tc.want {
			t.Fatalf("status %d => %v/%v, want failed/%v", tc.status, r.Status(), r.Errno(), tc.want)
		}
	}
}

// A 429 with Retry-After parks the grant: the next request waits out the
// server-requested cooldown.
func TestRetryAfterParksTheGrant(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	srv.status = http.StatusTooManyRequests
	srv.body = `{"kind":"Status","message":"slow down"}`
	srv.retryAfter = "7"
	h := newTestHandler(srv, fixtureResources())
	// Drive the limiter on a virtual clock so we can observe the cooldown.
	_, clk := driveLimiterOnFakeClock(h.Client.limiter)

	args := `{"operation":"get","resource":"pods","namespace":"default","name":"web-0"}`
	if r := dispatch(t, h, context.Background(), args); r.Errno() != sys.ErrnoTransient {
		t.Fatalf("429 => %v, want transient", r.Errno())
	}
	start := clk.now()
	dispatch(t, h, context.Background(), args)
	if elapsed := clk.now().Sub(start); elapsed < 7*time.Second {
		t.Fatalf("second request went after %v, want to wait out the 7s Retry-After", elapsed)
	}
}

func driveLimiterOnFakeClock(l *rateLimiter) (*rateLimiter, *fakeClock) {
	clk := &fakeClock{t: time.Unix(2_000_000, 0)}
	l.now = clk.now
	l.sleep = clk.sleep
	l.last = clk.now()
	return l, clk
}

// A body over the byte bound is refused (with a narrow-the-query hint) rather
// than truncated into unparseable JSON.
func TestOversizedResponseRefused(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	big := `{"kind":"PodList","items":["` + strings.Repeat("x", 2048) + `"]}`
	srv.body = big
	h := newTestHandler(srv, fixtureResources())
	h.Client.maxBytes = 512

	r := dispatch(t, h, context.Background(), `{"operation":"list","resource":"pods","namespace":"default"}`)
	if r.Status() != sys.StatusFailed || r.Errno() != sys.ErrnoInvalidArgs {
		t.Fatalf("oversized => %v/%v, want failed/invalid_args", r.Status(), r.Errno())
	}
	if !strings.Contains(r.Message(), "narrow the query") {
		t.Fatalf("oversized message unhelpful: %q", r.Message())
	}
}

// A successful read carries the resource's source labels and the credential
// provenance (the fingerprint, never the token).
func TestResultLabels(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	srv.body = `{"kind":"Pod","metadata":{"name":"web-0"}}`
	h := newTestHandler(srv, fixtureResources())

	r := dispatch(t, h, context.Background(), `{"operation":"get","resource":"pods","namespace":"default","name":"web-0"}`)
	got := map[string]bool{}
	for _, l := range r.Labels() {
		got[l] = true
	}
	if !got["k8s"] {
		t.Fatalf("result labels %v lack the resource's source label", r.Labels())
	}
	if !got["credential:k8s-serviceaccount@abcdef012345"] {
		t.Fatalf("result labels %v lack the credential provenance", r.Labels())
	}
}

func TestEndpointMustBeHTTPS(t *testing.T) {
	if _, err := ExplicitAccess("http://api.example.com", "", "tok"); err == nil {
		t.Fatal("plain-http endpoint accepted; a bearer token must ride TLS")
	}
	if _, err := ExplicitAccess("https://api.example.com/some/path", "", "tok"); err == nil {
		t.Fatal("endpoint with a path accepted; want scheme+host only")
	}
	if _, err := ExplicitAccess("https://api.example.com", "", ""); err == nil {
		t.Fatal("empty token accepted")
	}
	if _, err := ExplicitAccess("https://api.example.com:6443", "", "tok"); err != nil {
		t.Fatalf("valid https endpoint rejected: %v", err)
	}
}
