// Package internet is the core.internet driver: HTTP requests of any method,
// limited to the (method, origin) pairs the grant allows.
//
//	registration.go  a grant's config → the allowlist, the entries, the credentials
//	handler.go       one call: attach the host-held credentials and send
//	policy.go        the allowlist
//	client.go        the bounded HTTP client and its SSRF guard
//
// core.httpTemplate and core.openaiApi send through the same client.
package internet

// Capability is the syscall a core.internet grant serves. The request's HTTP
// method names the operation.
const Capability = "core.internet"

// AnyMethod is the method wildcard in a policy rule: it matches every HTTP
// method against the rule's origin.
const AnyMethod = "*"

// Request is one HTTP request a program asks the host to make. The grant's
// Policy decides which (method, origin) pairs are allowed.
type Request struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// Response is what the program observes: the final URL (after redirects), the
// status, the headers, the body up to the byte bound, and whether the bound cut
// it.
type Response struct {
	URL       string            `json:"url"`
	Status    int               `json:"status"`
	Headers   map[string]string `json:"headers,omitempty"`
	Body      string            `json:"body"`
	Truncated bool              `json:"truncated,omitempty"`
}
