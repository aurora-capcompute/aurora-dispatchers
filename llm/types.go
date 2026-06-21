package llm

import "context"

// Message is the minimal chat message shape shared with the guest.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest is the llm.chat host-call request.
type ChatRequest struct {
	Messages []Message `json:"messages"`
	JSON     bool      `json:"json"`
}

// ChatResponse is the llm.chat host-call response.
type ChatResponse struct {
	Content string `json:"content"`
}

// Client owns one LLM side-effect boundary.
type Client interface {
	Chat(ctx context.Context, request ChatRequest) (ChatResponse, error)
}
