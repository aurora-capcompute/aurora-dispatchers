package mcp_test

import (
	"github.com/aurora-capcompute/aurora-dispatchers/mcp"
	"bufio"
	"github.com/aurora-capcompute/capcompute/dispatcher"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestStdioDiscoveryAndCall(t *testing.T) {
	config := mcp.ServerConfig{
		ID:      "demo",
		Command: os.Args[0],
		Args:    []string{"-test.run=TestMCPHelperProcess"},
		Env:     map[string]string{"AURORA_MCP_HELPER": "1"},
	}
	value, err := mcp.NewDispatcher[string](context.Background(), config, nil)
	if err != nil {
		t.Fatalf("new dispatcher: %v", err)
	}
	capabilities := value.Capabilities()
	if len(capabilities) != 1 || capabilities[0].Name != "mcp.demo.echo" {
		t.Fatalf("capabilities = %+v", capabilities)
	}
	outcome, err := value.Dispatch(context.Background(), "run", dispatcher.Call{
		Name: "mcp.demo.echo", Args: json.RawMessage(`{"text":"hello"}`),
	}, dispatcher.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if outcome.Kind() != dispatcher.OutcomeResult ||
		!json.Valid(outcome.Result()) {
		t.Fatalf("outcome = %#v", outcome)
	}
}

func TestMCPHelperProcess(t *testing.T) {
	if os.Getenv("AURORA_MCP_HELPER") != "1" {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var request struct {
			ID     int64           `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			os.Exit(2)
		}
		if request.ID == 0 {
			continue
		}
		var result any
		switch request.Method {
		case "initialize":
			result = map[string]any{"protocolVersion": mcp.ProtocolVersion, "capabilities": map[string]any{}}
		case "tools/list":
			result = map[string]any{"tools": []any{map[string]any{
				"name": "echo", "description": "Echo input",
				"inputSchema": map[string]any{"type": "object"},
			}}}
		case "tools/call":
			result = map[string]any{"content": []any{map[string]any{"type": "text", "text": "hello"}}}
		default:
			_ = encoder.Encode(map[string]any{
				"jsonrpc": "2.0", "id": request.ID,
				"error": map[string]any{"code": -32601, "message": fmt.Sprintf("unknown %s", request.Method)},
			})
			continue
		}
		_ = encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
	}
	os.Exit(0)
}
