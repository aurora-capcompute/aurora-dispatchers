package httptemplate_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aurora-capcompute/aurora-dispatchers/httptemplate"
	"github.com/aurora-capcompute/aurora-dispatchers/internet"
	"github.com/aurora-capcompute/capcompute/sys"
)

func mustParse(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return v
}

func templateCall(operation string, fields map[string]any) sys.Syscall {
	args := map[string]any{"operation": operation}
	for k, v := range fields {
		args[k] = v
	}
	raw, _ := json.Marshal(args)
	return sys.Syscall{Abi: sys.ABIVersion, Name: "core.httpTemplate", Args: raw}
}

func searchHandler(t *testing.T, client internet.Doer) httptemplate.Handler {
	return httptemplate.Handler{
		Client: client,
		Operation: httptemplate.Operation{
			Name:             "search",
			Method:           "POST",
			BaseURL:          "https://onyx.example.com",
			Path:             "/api/chat/send-message-simple-api",
			Body:             mustParse(t, `{"message":"{{query}}","persona_id":0}`),
			Params:           map[string]httptemplate.Param{"query": {Type: "string"}},
			Headers:          map[string]string{"Authorization": "Bearer tok-abc"},
			CredentialLabels: []string{"credential:ONYX_TOKEN@abc123def456"},
		},
	}
}

// The guest fills only {query}; the host builds the exact request — method, host,
// path, and body shape fixed — and attaches the credential the guest never sees.
// recordingClient captures the request that actually reached the network, so a
// test can assert on what the template rendered.
type recordingClient struct {
	seen     internet.Request
	response internet.Response
}

func (c *recordingClient) Do(_ context.Context, req internet.Request) (internet.Response, error) {
	c.seen = req
	return c.response, nil
}

func TestTemplateRendersRequestAndInjectsCredential(t *testing.T) {
	client := &recordingClient{response: internet.Response{Status: 200, Body: "ok"}}
	handler := searchHandler(t, client)

	result, err := handler.DispatchCall(context.Background(), templateCall("search", map[string]any{"query": "What is Hwaas?"}))
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Status() != sys.StatusResult {
		t.Fatalf("result = %#v, want a successful result", result)
	}
	if client.seen.Method != "POST" || client.seen.URL != "https://onyx.example.com/api/chat/send-message-simple-api" {
		t.Fatalf("request = %s %s, want the fixed method/URL", client.seen.Method, client.seen.URL)
	}
	if got := client.seen.Headers["Authorization"]; got != "Bearer tok-abc" {
		t.Fatalf("Authorization = %q, want the injected credential", got)
	}
	// A JSON body must be declared, or a JSON API rejects it as unparsed (422).
	if got := client.seen.Headers["Content-Type"]; got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(client.seen.Body), &body); err != nil {
		t.Fatalf("body is not valid JSON: %q", client.seen.Body)
	}
	if body["message"] != "What is Hwaas?" || body["persona_id"] != float64(0) {
		t.Fatalf("body = %v, want {message:the question, persona_id:0}", body)
	}
}

// A guest value laden with JSON metacharacters is placed structurally, so it
// cannot break out of its string slot to add or overwrite fields.
func TestTemplateBodySubstitutionIsInjectionSafe(t *testing.T) {
	client := &recordingClient{response: internet.Response{Status: 200}}
	handler := searchHandler(t, client)

	attack := `hi","persona_id":999,"admin":true,"x":"`
	if _, err := handler.DispatchCall(context.Background(), templateCall("search", map[string]any{"query": attack})); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(client.seen.Body), &body); err != nil {
		t.Fatalf("body is not valid JSON after a hostile value: %q", client.seen.Body)
	}
	if body["message"] != attack {
		t.Fatalf("message = %q, want the hostile value carried verbatim as a string", body["message"])
	}
	if body["persona_id"] != float64(0) {
		t.Fatalf("SECURITY: guest value overwrote persona_id: %v", body["persona_id"])
	}
	if _, injected := body["admin"]; injected {
		t.Fatal("SECURITY: guest value injected a new field into the body")
	}
}

// Path and query placeholders are percent-encoded, so a value cannot traverse the
// path or smuggle extra query parameters.
func TestTemplatePathAndQueryAreEncoded(t *testing.T) {
	client := &recordingClient{response: internet.Response{Status: 200}}
	handler := httptemplate.Handler{
		Client: client,
		Operation: httptemplate.Operation{
			Name:    "doc",
			Method:  "GET",
			BaseURL: "https://onyx.example.com",
			Path:    "/api/docs/{{id}}",
			Query:   map[string]string{"q": "{{term}}"},
			Params: map[string]httptemplate.Param{
				"id":   {Type: "string"},
				"term": {Type: "string"},
			},
		},
	}
	_, err := handler.DispatchCall(context.Background(), templateCall("doc", map[string]any{"id": "a/../secret", "term": "x&y=z"}))
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// The slash in the id is escaped (no path traversal), and the query value's
	// & and = are encoded (no extra parameters).
	want := "https://onyx.example.com/api/docs/a%2F..%2Fsecret?q=x%26y%3Dz"
	if client.seen.URL != want {
		t.Fatalf("URL = %q, want %q", client.seen.URL, want)
	}
}

// A typed parameter is substituted as its JSON type (a number, not a string).
func TestTemplateTypedParamSubstitution(t *testing.T) {
	client := &recordingClient{response: internet.Response{Status: 200}}
	handler := httptemplate.Handler{
		Client: client,
		Operation: httptemplate.Operation{
			Name:    "search",
			Method:  "POST",
			BaseURL: "https://onyx.example.com",
			Path:    "/s",
			Body:    mustParse(t, `{"top_k":"{{k}}"}`),
			Params:  map[string]httptemplate.Param{"k": {Type: "integer"}},
		},
	}
	if _, err := handler.DispatchCall(context.Background(), templateCall("search", map[string]any{"k": 5})); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if client.seen.Body != `{"top_k":5}` {
		t.Fatalf("body = %q, want top_k as the number 5", client.seen.Body)
	}
}

// Flow policy and approval used to be enforced here and are now the operation's
// entry's — the sink guard in the runtime's monitor, approval in
// capability.Dispatcher. Credential provenance is published as the entry's
// labels; httptemplate/registration_test.go covers it.
