package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultOpenAIBaseURL = "https://api.openai.com/v1"
	DefaultOpenAIModel   = "gpt-5.4"
)

// OpenAIConfig configures an OpenAI-compatible Chat Completions client.
type OpenAIConfig struct {
	APIKey      string
	BaseURL     string
	Model       string
	Timeout     time.Duration
	MaxRetries  int
	RetryWait   time.Duration
	MaxTokens   int
	Temperature *float64
	HTTPClient  *http.Client
}

func DefaultOpenAIConfig() OpenAIConfig {
	temperature := 0.0
	return OpenAIConfig{
		BaseURL:     DefaultOpenAIBaseURL,
		Model:       DefaultOpenAIModel,
		Timeout:     30 * time.Second,
		MaxRetries:  2,
		RetryWait:   100 * time.Millisecond,
		MaxTokens:   1024,
		Temperature: &temperature,
	}
}

func OpenAIConfigFromEnv() OpenAIConfig {
	config := DefaultOpenAIConfig()
	config.APIKey = os.Getenv("OPENAI_API_KEY")
	if value := strings.TrimSpace(os.Getenv("OPENAI_BASE_URL")); value != "" {
		config.BaseURL = value
	}
	if value := strings.TrimSpace(os.Getenv("OPENAI_MODEL")); value != "" {
		config.Model = value
	}
	if value := strings.TrimSpace(firstEnv("OPENAI_TIMEOUT", "AURORA_LLM_TIMEOUT")); value != "" {
		if parsed, err := parseDuration(value); err == nil {
			config.Timeout = parsed
		}
	}
	if value := strings.TrimSpace(firstEnv("OPENAI_MAX_RETRIES", "OPENAI_RETRIES", "AURORA_LLM_RETRIES")); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed >= 0 {
			config.MaxRetries = parsed
		}
	}
	if value := strings.TrimSpace(firstEnv("OPENAI_MAX_TOKENS", "AURORA_LLM_MAX_TOKENS")); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			config.MaxTokens = parsed
		}
	}
	if value := strings.TrimSpace(firstEnv("OPENAI_TEMPERATURE", "AURORA_LLM_TEMPERATURE")); value != "" {
		if parsed, err := strconv.ParseFloat(value, 64); err == nil {
			config.Temperature = &parsed
		}
	}
	return config
}

type OpenAIClient struct {
	apiKey      string
	endpoint    string
	model       string
	maxRetries  int
	retryWait   time.Duration
	maxTokens   int
	temperature *float64
	httpClient  *http.Client
}

func NewOpenAIClient(config OpenAIConfig) (*OpenAIClient, error) {
	if strings.TrimSpace(config.APIKey) == "" {
		return nil, errors.New("OPENAI_API_KEY is required")
	}
	baseURL := strings.TrimRight(strings.TrimSpace(config.BaseURL), "/")
	if baseURL == "" {
		baseURL = DefaultOpenAIBaseURL
	}
	model := strings.TrimSpace(config.Model)
	if model == "" {
		model = DefaultOpenAIModel
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}
	return &OpenAIClient{
		apiKey:      config.APIKey,
		endpoint:    baseURL + "/chat/completions",
		model:       model,
		maxRetries:  config.MaxRetries,
		retryWait:   config.RetryWait,
		maxTokens:   config.MaxTokens,
		temperature: config.Temperature,
		httpClient:  httpClient,
	}, nil
}

func (c *OpenAIClient) Chat(ctx context.Context, request ChatRequest) (ChatResponse, error) {
	payload := chatCompletionsRequest{
		Model:    c.model,
		Messages: openAIMessages(request.Messages),
	}
	if request.JSON {
		payload.ResponseFormat = &responseFormat{Type: "json_object"}
	}
	if c.maxTokens > 0 {
		payload.MaxTokens = c.maxTokens
	}
	if c.temperature != nil {
		payload.Temperature = c.temperature
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("encode openai request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		response, err := c.doChatAttempt(ctx, body)
		if err == nil {
			return response, nil
		}
		lastErr = err
		if !isRetryableError(err) || attempt == c.maxRetries {
			break
		}
		if err := waitForRetry(ctx, c.retryWait); err != nil {
			return ChatResponse{}, err
		}
	}
	return ChatResponse{}, lastErr
}

func (c *OpenAIClient) doChatAttempt(ctx context.Context, body []byte) (ChatResponse, error) {
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return ChatResponse{}, fmt.Errorf("create openai request: %w", err)
	}
	httpRequest.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpRequest.Header.Set("Content-Type", "application/json")

	httpResponse, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return ChatResponse{}, retryableTransportError{err: err}
	}
	defer httpResponse.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(httpResponse.Body, 1<<20))
	if err != nil {
		return ChatResponse{}, fmt.Errorf("read openai response: %w", err)
	}
	if httpResponse.StatusCode == http.StatusTooManyRequests || httpResponse.StatusCode >= 500 {
		return ChatResponse{}, retryableStatusError{err: providerError(httpResponse.StatusCode, responseBody)}
	}
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		return ChatResponse{}, providerError(httpResponse.StatusCode, responseBody)
	}

	var decoded chatCompletionsResponse
	if err := json.Unmarshal(responseBody, &decoded); err != nil {
		return ChatResponse{}, fmt.Errorf("decode openai response: %w", err)
	}
	if len(decoded.Choices) == 0 {
		return ChatResponse{}, errors.New("openai response contained no choices")
	}
	return ChatResponse{Content: decoded.Choices[0].Message.Content}, nil
}

type chatCompletionsRequest struct {
	Model          string          `json:"model"`
	Messages       []openAIMessage `json:"messages"`
	ResponseFormat *responseFormat `json:"response_format,omitempty"`
	MaxTokens      int             `json:"max_completion_tokens,omitempty"`
	Temperature    *float64        `json:"temperature,omitempty"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type responseFormat struct {
	Type string `json:"type"`
}

type chatCompletionsResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func openAIMessages(messages []Message) []openAIMessage {
	out := make([]openAIMessage, 0, len(messages))
	for _, message := range messages {
		role := strings.ToLower(strings.TrimSpace(message.Role))
		content := message.Content
		switch role {
		case "system", "user", "assistant":
		case "tool":
			role = "user"
			content = "Tool observation:\n" + content
		default:
			role = "user"
		}
		out = append(out, openAIMessage{Role: role, Content: content})
	}
	return out
}

func providerError(status int, body []byte) error {
	var decoded struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &decoded); err == nil && decoded.Error.Message != "" {
		return fmt.Errorf("openai provider error %d: %s", status, decoded.Error.Message)
	}
	if len(body) > 0 {
		return fmt.Errorf("openai provider error %d: %s", status, strings.TrimSpace(string(body)))
	}
	return fmt.Errorf("openai provider error %d", status)
}

type retryableStatusError struct {
	err error
}

func (e retryableStatusError) Error() string {
	return e.err.Error()
}

func (e retryableStatusError) Unwrap() error {
	return e.err
}

type retryableTransportError struct {
	err error
}

func (e retryableTransportError) Error() string {
	return e.err.Error()
}

func (e retryableTransportError) Unwrap() error {
	return e.err
}

func isRetryableError(err error) bool {
	var status retryableStatusError
	if errors.As(err, &status) {
		return true
	}
	var transport retryableTransportError
	return errors.As(err, &transport)
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func parseDuration(value string) (time.Duration, error) {
	if parsed, err := time.ParseDuration(value); err == nil {
		return parsed, nil
	}
	seconds, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	return time.Duration(seconds) * time.Second, nil
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return ""
}
