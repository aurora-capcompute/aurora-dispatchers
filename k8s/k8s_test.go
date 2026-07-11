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
	rec := &recordingServer{status: 200, body: `{"kind":"Pod","metadata":{"name":"web-0"}}`}
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
		{Verb: "get", Group: "", Version: "v1", Resource: "pods", Namespaces: []string{"default", "kube-system"}, Labels: []string{"k8s"}},
		{Verb: "get", Group: "", Version: "v1", Resource: "nodes", ClusterScoped: true},
		{Verb: "get", Group: "apps", Version: "v1", Resource: "deployments", Namespaces: []string{"default"}},
		{Verb: "get", Group: "", Version: "v1", Resource: "configmaps", Namespaces: []string{"default"}, MetadataOnly: true},
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

// Every operation the driver performs is a single-object GET — there is no other
// verb or method in the code, so the fake server must only ever see GET.
func TestOnlyEverIssuesGET(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	h := newTestHandler(srv, fixtureResources())
	ctx := context.Background()

	calls := []string{
		`{"operation":"get","resource":"pods","namespace":"default","name":"web-0"}`,
		`{"operation":"get","resource":"nodes","name":"node-1"}`,
		`{"operation":"get","group":"apps","resource":"deployments","namespace":"default","name":"web"}`,
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

// list (and every other non-get operation) is not accepted — the code has no
// path for it.
func TestListIsNotAnOperation(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	h := newTestHandler(srv, fixtureResources())
	for _, op := range []string{"list", "watch", "create", "delete"} {
		args := `{"operation":"` + op + `","resource":"pods","namespace":"default"}`
		r := dispatch(t, h, context.Background(), args)
		if r.Status() != sys.StatusFailed || r.Errno() != sys.ErrnoInvalidArgs {
			t.Fatalf("operation %q => %v/%v, want failed/invalid_args", op, r.Status(), r.Errno())
		}
		if _, _, _, _, _, hits := srv.snapshot(); hits != 0 {
			t.Fatalf("operation %q reached the API server", op)
		}
	}
}

func TestGetPathAndCacheRead(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	h := newTestHandler(srv, fixtureResources())

	r := dispatch(t, h, context.Background(), `{"operation":"get","resource":"pods","namespace":"default","name":"web-0"}`)
	if r.Status() != sys.StatusResult {
		t.Fatalf("status = %v: %s", r.Status(), r.Message())
	}
	_, path, query, auth, accept, _ := srv.snapshot()
	if path != "/api/v1/namespaces/default/pods/web-0" {
		t.Fatalf("path = %q", path)
	}
	if query != "resourceVersion=0" {
		t.Fatalf("query = %q, want exactly resourceVersion=0 (cache read, nothing else)", query)
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

func TestMetadataOnlyAcceptHeader(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	h := newTestHandler(srv, fixtureResources())
	ctx := context.Background()

	// A get returns the full object by default.
	dispatch(t, h, ctx, `{"operation":"get","resource":"pods","namespace":"default","name":"web-0"}`)
	if _, _, _, _, accept, _ := srv.snapshot(); accept != "application/json" {
		t.Fatalf("default get accept = %q, want full object", accept)
	}

	// The grant forces metadata-only on configmaps: the object body never leaves
	// the API server.
	dispatch(t, h, ctx, `{"operation":"get","resource":"configmaps","namespace":"default","name":"cfg"}`)
	if _, _, _, _, accept, _ := srv.snapshot(); accept != "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1" {
		t.Fatalf("configmap get accept = %q, want metadata", accept)
	}

	// A request may tighten any get to metadata-only.
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
		{"ungranted namespace", `{"operation":"get","resource":"pods","namespace":"prod","name":"web-0"}`},
		{"namespace on cluster-scoped", `{"operation":"get","resource":"nodes","namespace":"default","name":"node-1"}`},
		{"namespaced get without namespace", `{"operation":"get","resource":"pods","name":"web-0"}`},
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

// A resource whose grant does not include the verb is refused — the per-resource
// verb allowlist gates the operation (the hook a future operation slots into).
func TestVerbNotGrantedIsRefused(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	// A permission for a different verb does not authorize a get.
	resources := []Permission{{Verb: "watch", Group: "", Version: "v1", Resource: "pods", Namespaces: []string{"default"}}}
	h := newTestHandler(srv, resources)
	r := dispatch(t, h, context.Background(), `{"operation":"get","resource":"pods","namespace":"default","name":"web-0"}`)
	if r.Status() != sys.StatusFailed || r.Errno() != sys.ErrnoDenied {
		t.Fatalf("ungranted verb = %v/%v, want failed/denied", r.Status(), r.Errno())
	}
	if _, _, _, _, _, hits := srv.snapshot(); hits != 0 {
		t.Fatal("a verb-denied read reached the API server")
	}
}

// A "*" namespace grant authorizes a get in any namespace the guest names — a
// single object, in whichever namespace, still from cache.
func TestWildcardNamespaceAllowsAnyNamespace(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	resources := []Permission{{Verb: "get", Group: "", Version: "v1", Resource: "pods", Namespaces: []string{"*"}}}
	h := newTestHandler(srv, resources)

	for _, ns := range []string{"default", "kube-system", "some-team-ns"} {
		r := dispatch(t, h, context.Background(),
			`{"operation":"get","resource":"pods","namespace":"`+ns+`","name":"web-0"}`)
		if r.Status() != sys.StatusResult {
			t.Fatalf("get in %q = %v (%s)", ns, r.Status(), r.Message())
		}
		if _, path, _, _, _, _ := srv.snapshot(); path != "/api/v1/namespaces/"+ns+"/pods/web-0" {
			t.Fatalf("path = %q for namespace %q", path, ns)
		}
	}
	// A get still requires a namespace even under the wildcard (get is one object).
	if r := dispatch(t, h, context.Background(), `{"operation":"get","resource":"pods","name":"web-0"}`); r.Status() != sys.StatusFailed {
		t.Fatalf("get without a namespace = %v, want failed", r.Status())
	}
}

// The Secret-data floor is a request-time hard guarantee that does not depend on
// config validation: a Permission naming core secrets without metadata_only —
// one normalization should never emit — still cannot read a Secret body. The
// driver refuses before any request unless the read is metadata-only.
func TestSecretDataFloorHoldsAtRequestTime(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	// Construct the grant directly, bypassing config normalization, to prove the
	// floor stands on its own.
	resources := []Permission{{Verb: "get", Group: "", Version: "v1", Resource: "secrets", Namespaces: []string{"default"}}}
	h := newTestHandler(srv, resources)

	r := dispatch(t, h, context.Background(), `{"operation":"get","resource":"secrets","namespace":"default","name":"db"}`)
	if r.Status() != sys.StatusFailed || r.Errno() != sys.ErrnoInvalidArgs {
		t.Fatalf("secret data read = %v/%v, want failed/invalid_args", r.Status(), r.Errno())
	}
	if _, _, _, _, _, hits := srv.snapshot(); hits != 0 {
		t.Fatal("a secret-data read reached the API server")
	}
	// A metadata-only read of the same Secret is allowed — only the body is barred.
	r = dispatch(t, h, context.Background(), `{"operation":"get","resource":"secrets","namespace":"default","name":"db","metadata_only":true}`)
	if r.Status() != sys.StatusResult {
		t.Fatalf("metadata-only secret read = %v (%s)", r.Status(), r.Message())
	}
}

// Guest-supplied identity fields that could inject a path are refused before any
// request is built.
func TestPathInjectionRejected(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	h := newTestHandler(srv, fixtureResources())
	ctx := context.Background()

	injections := []string{
		`{"operation":"get","resource":"pods","namespace":"default","name":"../../secrets/db"}`,
		`{"operation":"get","resource":"pods","namespace":"default/../kube-system","name":"web-0"}`,
		`{"operation":"get","resource":"pods","namespace":"default","name":"web-0?watch=true"}`,
		`{"operation":"get","resource":"po ds","namespace":"default","name":"x"}`,
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
	resources := []Permission{{Verb: "get", Group: "", Version: "v1", Resource: "pods",
		Namespaces: []string{"default"}, Taints: []string{"untrusted_web"}}}
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
	resources := []Permission{{Verb: "get", Group: "", Version: "v1", Resource: "pods",
		Namespaces: []string{"default"}, RequireApproval: true}}
	h := newTestHandler(srv, resources)
	args := `{"operation":"get","resource":"pods","namespace":"default","name":"web-0"}`

	if r := dispatch(t, h, context.Background(), args); r.Status() != sys.StatusYield {
		t.Fatalf("unapproved = %v, want yield", r.Status())
	}
	if _, _, _, _, _, hits := srv.snapshot(); hits != 0 {
		t.Fatal("an unapproved read reached the API server")
	}
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

// A body over the byte bound is refused (with a metadata_only hint) rather than
// truncated into unparseable JSON.
func TestOversizedResponseRefused(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
	srv.body = `{"kind":"Pod","data":"` + strings.Repeat("x", 2048) + `"}`
	h := newTestHandler(srv, fixtureResources())
	h.Client.maxBytes = 512

	r := dispatch(t, h, context.Background(), `{"operation":"get","resource":"pods","namespace":"default","name":"web-0"}`)
	if r.Status() != sys.StatusFailed || r.Errno() != sys.ErrnoInvalidArgs {
		t.Fatalf("oversized => %v/%v, want failed/invalid_args", r.Status(), r.Errno())
	}
	if !strings.Contains(r.Message(), "metadata_only") {
		t.Fatalf("oversized message unhelpful: %q", r.Message())
	}
}

// A successful read carries the resource's source labels and the credential
// provenance (the fingerprint, never the token).
func TestResultLabels(t *testing.T) {
	srv := newRecordingServer()
	defer srv.Close()
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
