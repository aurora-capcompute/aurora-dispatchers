package openaillm

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aurora-capcompute/aurora-dispatchers/registry"
)

const (
	defaultBaseURL         = "https://api.openai.com/v1"
	defaultTimeout         = 2 * time.Minute
	defaultMaxRequestBytes = 1 << 20
)

var headerPattern = regexp.MustCompile(`^[!#$%&'*+\-.^_` + "`" + `|~0-9A-Za-z]+$`)

type Settings struct {
	BaseURL string `json:"base_url,omitempty"`
	// APIKey is the provider credential, a {"secret":"NAME"} reference resolved
	// host-side so the value never enters the manifest, journal, or guest.
	APIKey            registry.Secret   `json:"api_key,omitempty"`
	APIKeyOptional    bool              `json:"api_key_optional,omitempty"`
	DefaultModel      string            `json:"default_model,omitempty"`
	AllowedModels     []string          `json:"allowed_models,omitempty"`
	Organization      string            `json:"organization,omitempty"`
	Project           string            `json:"project,omitempty"`
	Timeout           string            `json:"timeout,omitempty"`
	MaxRetries        *int              `json:"max_retries,omitempty"`
	MaxRequestBytes   int               `json:"max_request_bytes,omitempty"`
	AllowInsecureHTTP bool              `json:"allow_insecure_http,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
}

type normalizedSettings struct {
	Settings
	timeout time.Duration
	// apiKey is the resolved credential value, set by Configure after resolving
	// Settings.APIKey through the secret resolver. It is never persisted.
	apiKey string
}

func normalizeSettings(settings Settings) (normalizedSettings, error) {
	settings.BaseURL = strings.TrimRight(strings.TrimSpace(settings.BaseURL), "/")
	if settings.BaseURL == "" {
		settings.BaseURL = defaultBaseURL
	}
	if err := validateBaseURL(settings.BaseURL, settings.AllowInsecureHTTP); err != nil {
		return normalizedSettings{}, err
	}

	settings.DefaultModel = strings.TrimSpace(settings.DefaultModel)
	settings.Organization = strings.TrimSpace(settings.Organization)
	settings.Project = strings.TrimSpace(settings.Project)
	settings.AllowedModels = cleanList(settings.AllowedModels)
	// A call that names no model runs on the default, so the default must be
	// one the grant allows.
	if settings.DefaultModel != "" && len(settings.AllowedModels) > 0 && !slices.Contains(settings.AllowedModels, settings.DefaultModel) {
		return normalizedSettings{}, fmt.Errorf("default_model %q is not in allowed_models", settings.DefaultModel)
	}

	timeout := defaultTimeout
	if strings.TrimSpace(settings.Timeout) != "" {
		parsed, err := time.ParseDuration(settings.Timeout)
		if err != nil || parsed <= 0 {
			return normalizedSettings{}, fmt.Errorf("invalid timeout %q", settings.Timeout)
		}
		timeout = parsed
		settings.Timeout = parsed.String()
	}
	if settings.MaxRetries != nil && *settings.MaxRetries < 0 {
		return normalizedSettings{}, fmt.Errorf("max_retries must not be negative")
	}
	if settings.MaxRequestBytes < 0 {
		return normalizedSettings{}, fmt.Errorf("max_request_bytes must not be negative")
	}
	if settings.MaxRequestBytes == 0 {
		settings.MaxRequestBytes = defaultMaxRequestBytes
	}

	headers := make(map[string]string, len(settings.Headers))
	for name, value := range settings.Headers {
		name = http.CanonicalHeaderKey(strings.TrimSpace(name))
		if !headerPattern.MatchString(name) {
			return normalizedSettings{}, fmt.Errorf("invalid header name %q", name)
		}
		switch name {
		case "Authorization", "Content-Length", "Host":
			return normalizedSettings{}, fmt.Errorf("header %q cannot be set via headers", name)
		}
		headers[name] = value
	}
	settings.Headers = headers

	return normalizedSettings{Settings: settings, timeout: timeout}, nil
}

func validateBaseURL(raw string, allowInsecureHTTP bool) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid base_url: %w", err)
	}
	if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("base_url must contain only scheme, host, and path")
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if !allowInsecureHTTP {
			return fmt.Errorf("plain HTTP base_url requires allow_insecure_http")
		}
		host := parsed.Hostname()
		if host == "localhost" {
			return nil
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("plain HTTP is only allowed for loopback hosts")
		}
		return nil
	default:
		return fmt.Errorf("base_url scheme must be https")
	}
}

// cleanList trims, sorts and deduplicates a list, dropping empty values.
func cleanList(values []string) []string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			cleaned = append(cleaned, value)
		}
	}
	slices.Sort(cleaned)
	return slices.Compact(cleaned)
}
