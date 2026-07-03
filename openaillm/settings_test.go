package openaillm

import (
	"reflect"
	"testing"
)

func TestNormalizeSettingsCleansPolicy(t *testing.T) {
	settings, err := normalizeSettings(Settings{
		BaseURL:       "https://llm.example.com/v1/",
		APIKey:        "sk-test",
		AllowedModels: []string{" model-b ", "model-a", "model-a"},
		Timeout:       "120s",
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if settings.BaseURL != "https://llm.example.com/v1" {
		t.Fatalf("base URL = %q", settings.BaseURL)
	}
	if settings.APIKey != "sk-test" {
		t.Fatalf("API key = %q", settings.APIKey)
	}
	if !reflect.DeepEqual(settings.AllowedModels, []string{"model-a", "model-b"}) {
		t.Fatalf("allowed models = %#v", settings.AllowedModels)
	}
	if settings.Timeout != "2m0s" {
		t.Fatalf("timeout = %q", settings.Timeout)
	}
}

func TestPlainHTTPRestrictedToExplicitLoopback(t *testing.T) {
	tests := []struct {
		name     string
		settings Settings
		wantErr  bool
	}{
		{
			name:     "not enabled",
			settings: Settings{BaseURL: "http://127.0.0.1:11434/v1"},
			wantErr:  true,
		},
		{
			name: "loopback enabled",
			settings: Settings{
				BaseURL:           "http://127.0.0.1:11434/v1",
				AllowInsecureHTTP: true,
			},
		},
		{
			name: "remote HTTP rejected",
			settings: Settings{
				BaseURL:           "http://llm.example.com/v1",
				AllowInsecureHTTP: true,
			},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := normalizeSettings(test.settings)
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestSensitiveHeadersCannotBeSet(t *testing.T) {
	_, err := normalizeSettings(Settings{
		Headers: map[string]string{"Authorization": "Bearer token"},
	})
	if err == nil {
		t.Fatal("expected Authorization header validation error")
	}
}
