package openaillm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"

	"github.com/aurora-capcompute/aurora-dispatchers/internet"
)

// maxProviderResponseBytes bounds a provider response body so a hostile or
// DNS-rebound endpoint cannot exhaust host memory. Generous — provider payloads
// (long completions, large embedding batches) are big but not unbounded.
const maxProviderResponseBytes = 32 << 20 // 32 MiB

type Client interface {
	Chat(context.Context, json.RawMessage) (json.RawMessage, error)
	Responses(context.Context, json.RawMessage) (json.RawMessage, error)
	Embeddings(context.Context, json.RawMessage) (json.RawMessage, error)
	Models(context.Context) (json.RawMessage, error)
}

type sdkClient struct {
	client  openai.Client
	timeout time.Duration
}

func NewClient(settings normalizedSettings) (Client, error) {
	if settings.apiKey == "" && !settings.APIKeyOptional {
		return nil, fmt.Errorf("api_key is required")
	}

	httpClient := &http.Client{
		Transport: guardedTransport(settings.BaseURL, settings.timeout),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("provider redirects are disabled")
		},
	}
	options := []option.RequestOption{
		option.WithBaseURL(settings.BaseURL),
		option.WithAPIKey(settings.apiKey),
		option.WithHTTPClient(httpClient),
		option.WithOrganization(settings.Organization),
		option.WithProject(settings.Project),
	}
	if settings.MaxRetries != nil {
		options = append(options, option.WithMaxRetries(*settings.MaxRetries))
	}
	for header, value := range settings.Headers {
		options = append(options, option.WithHeader(header, value))
	}
	// Construct the generic SDK client with explicit options so unrelated
	// OPENAI_* variables cannot silently alter a manifest-defined provider.
	return &sdkClient{client: openai.Client{Options: options}, timeout: settings.timeout}, nil
}

func (c *sdkClient) Chat(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	return c.post(ctx, "chat/completions", body)
}

func (c *sdkClient) Responses(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	return c.post(ctx, "responses", body)
}

func (c *sdkClient) Embeddings(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	return c.post(ctx, "embeddings", body)
}

func (c *sdkClient) Models(ctx context.Context) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var response json.RawMessage
	if err := c.client.Get(ctx, "models", nil, &response); err != nil {
		return nil, err
	}
	return response, nil
}

func (c *sdkClient) post(ctx context.Context, path string, body json.RawMessage) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var response json.RawMessage
	if err := c.client.Post(ctx, path, []byte(body), &response); err != nil {
		return nil, err
	}
	return response, nil
}

// guardedTransport builds the provider transport with a dial-time SSRF guard —
// it blocks connecting to a non-public address, defeating DNS rebinding of the
// (manifest-fixed, https-validated) provider host to an internal/metadata IP,
// which would otherwise ship the API key there — plus a response-size bound. A
// loopback base_url (local dev) opts out of the dial guard, since the dial is
// then legitimately to loopback.
func guardedTransport(baseURL string, timeout time.Duration) http.RoundTripper {
	allowLocal := false
	if u, err := url.Parse(baseURL); err == nil && u.Host != "" {
		allowLocal = internet.LoopbackHost(u.Host)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	dialer := &net.Dialer{Timeout: timeout}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if !allowLocal {
			if err := internet.GuardDialAddress(address); err != nil {
				return nil, err
			}
		}
		return dialer.DialContext(ctx, network, address)
	}
	return &boundedRoundTripper{next: transport}
}

// boundedRoundTripper caps each response body at maxProviderResponseBytes.
type boundedRoundTripper struct{ next http.RoundTripper }

func (b *boundedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := b.next.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	resp.Body = &boundedBody{inner: resp.Body, remaining: maxProviderResponseBytes}
	return resp, nil
}

type boundedBody struct {
	inner     io.ReadCloser
	remaining int64
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.remaining < 0 {
		return 0, fmt.Errorf("provider response exceeds %d bytes", int64(maxProviderResponseBytes))
	}
	// Read at most one byte past the cap so a body of exactly the cap ends on a
	// clean EOF, while a body over it trips the guard on the next read.
	if int64(len(p)) > b.remaining+1 {
		p = p[:b.remaining+1]
	}
	n, err := b.inner.Read(p)
	b.remaining -= int64(n)
	if b.remaining < 0 {
		return n, fmt.Errorf("provider response exceeds %d bytes", int64(maxProviderResponseBytes))
	}
	return n, err
}

func (b *boundedBody) Close() error { return b.inner.Close() }
