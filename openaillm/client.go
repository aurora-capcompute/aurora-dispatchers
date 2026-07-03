package openaillm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)

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
	if settings.APIKey == "" && !settings.APIKeyOptional {
		return nil, fmt.Errorf("api_key is required")
	}

	httpClient := &http.Client{
		Transport: http.DefaultTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("provider redirects are disabled")
		},
	}
	options := []option.RequestOption{
		option.WithBaseURL(settings.BaseURL),
		option.WithAPIKey(settings.APIKey),
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
