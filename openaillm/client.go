package openaillm

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"time"

	"github.com/aurora-capcompute/aurora-dispatchers/internet"
)

// maxProviderResponseBytes bounds a provider response body so a hostile or
// DNS-rebound endpoint cannot exhaust host memory. Generous — provider payloads
// (long completions, large embedding batches) are big but not unbounded.
const maxProviderResponseBytes = 32 << 20 // 32 MiB

// defaultMaxRetries is how many times a failed provider call is tried again
// when the grant sets no max_retries.
const defaultMaxRetries = 2

// maxErrorBodyBytes bounds how much of a provider's error body an error
// message quotes.
const maxErrorBodyBytes = 2000

// Client sends one request to the provider and returns its JSON body.
type Client interface {
	Do(ctx context.Context, method, path string, body json.RawMessage) (json.RawMessage, error)
}

// provider is the Client for one OpenAI-compatible endpoint. It sends through
// an internet.Client allowlisted to the endpoint's origin, so it shares
// core.internet's dial guard, size bounds and redirect policy. It tries a call
// again after a network error, a 429 or a 5xx.
type provider struct {
	http    *internet.Client
	baseURL string
	headers map[string]string
	retries int
}

func newProvider(settings normalizedSettings) (provider, error) {
	if settings.apiKey == "" && !settings.APIKeyOptional {
		return provider{}, fmt.Errorf("api_key is required")
	}
	// normalizeSettings validated the base URL.
	base, _ := url.Parse(settings.BaseURL)
	rule, err := internet.NewRule(internet.AnyMethod, base.Scheme+"://"+base.Host)
	if err != nil {
		return provider{}, err
	}
	client := internet.NewConfiguredClient(internet.NewPolicy(rule), settings.timeout,
		maxProviderResponseBytes, int64(settings.MaxRequestBytes))
	// A loopback base_url (local development) is the one private address the
	// provider may reach. Any other base_url is held to the dial guard, so a name
	// rebound to an internal address cannot receive the API key.
	client.AllowPrivateNetwork = internet.LoopbackHost(base.Host)

	headers := map[string]string{"Content-Type": "application/json", "Accept": "application/json"}
	if settings.apiKey != "" {
		headers["Authorization"] = "Bearer " + settings.apiKey
	}
	if settings.Organization != "" {
		headers["OpenAI-Organization"] = settings.Organization
	}
	if settings.Project != "" {
		headers["OpenAI-Project"] = settings.Project
	}
	maps.Copy(headers, settings.Headers)

	retries := defaultMaxRetries
	if settings.MaxRetries != nil {
		retries = *settings.MaxRetries
	}
	return provider{http: client, baseURL: settings.BaseURL, headers: headers, retries: retries}, nil
}

func (p provider) Do(ctx context.Context, method, path string, body json.RawMessage) (json.RawMessage, error) {
	request := internet.Request{Method: method, URL: p.baseURL + "/" + path, Headers: p.headers, Body: string(body)}
	for attempt := 0; ; attempt++ {
		response, err := p.http.Do(ctx, request)
		retryable := err != nil
		if err == nil {
			switch {
			case response.Truncated:
				return nil, fmt.Errorf("provider response exceeds %d bytes", maxProviderResponseBytes)
			case response.Status < 300:
				return json.RawMessage(response.Body), nil
			}
			err = fmt.Errorf("%s %s: %d %s", method, path, response.Status, truncateBytes(response.Body, maxErrorBodyBytes))
			retryable = response.Status == 429 || response.Status >= 500
		}
		if !retryable || attempt >= p.retries || ctx.Err() != nil {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(500<<attempt) * time.Millisecond):
		}
	}
}

func truncateBytes(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "…"
}
