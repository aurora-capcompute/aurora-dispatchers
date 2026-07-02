package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aurora-capcompute/capcompute/sys"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const ProtocolVersion = "2025-03-26"

type ServerConfig struct {
	ID      string            `json:"id"`
	Command string            `json:"command"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Dir     string            `json:"dir,omitempty"`
	Timeout time.Duration     `json:"-"`
}

type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type Dispatcher[K any] struct {
	*Handler
}

type Handler struct {
	config       ServerConfig
	tools        map[string]Tool
	capabilities []sys.Capability
}

func NewDispatcher[K any](ctx context.Context, config ServerConfig, allowedTools []string) (*Dispatcher[K], error) {
	handler, err := NewHandler(ctx, config, allowedTools)
	if err != nil {
		return nil, err
	}
	return &Dispatcher[K]{Handler: handler}, nil
}

func NewHandler(ctx context.Context, config ServerConfig, allowedTools []string) (*Handler, error) {
	if strings.TrimSpace(config.ID) == "" || strings.TrimSpace(config.Command) == "" {
		return nil, errors.New("mcp server id and command are required")
	}
	conn, err := start(ctx, config)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	tools, err := conn.listTools(ctx)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]struct{}, len(allowedTools))
	for _, name := range allowedTools {
		allowed[name] = struct{}{}
	}
	out := &Handler{config: config, tools: make(map[string]Tool)}
	for _, tool := range tools {
		if len(allowed) > 0 {
			if _, ok := allowed[tool.Name]; !ok {
				continue
			}
		}
		action := actionName(config.ID, tool.Name)
		out.tools[action] = tool
		schema := tool.InputSchema
		if len(schema) == 0 {
			schema = json.RawMessage(`{"type":"object"}`)
		}
		out.capabilities = append(out.capabilities, sys.Capability{
			Name:        action,
			Description: tool.Description,
			InputSchema: schema,
		})
	}
	return out, nil
}

func (d *Dispatcher[K]) Dispatch(ctx context.Context, _ K, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	return d.DispatchCall(ctx, call, auth)
}

func (d *Handler) DispatchCall(ctx context.Context, call sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	tool, ok := d.tools[call.Name]
	if !ok {
		return sys.FailCode(sys.ErrnoNotFound, "unknown MCP tool: "+call.Name), nil
	}
	var arguments any = map[string]any{}
	if len(call.Args) > 0 {
		if err := json.Unmarshal(call.Args, &arguments); err != nil {
			return sys.FailCode(sys.ErrnoInvalidArgs, "decode MCP arguments: "+err.Error()), nil
		}
	}
	conn, err := start(ctx, d.config)
	if err != nil {
		if ctx.Err() != nil {
			return sys.SyscallResult{}, ctx.Err()
		}
		return sys.FailCode(sys.ErrnoTransient, err.Error()), nil
	}
	defer conn.Close()
	result, err := conn.callTool(ctx, tool.Name, arguments)
	if err != nil {
		if ctx.Err() != nil {
			return sys.SyscallResult{}, ctx.Err()
		}
		return sys.FailCode(sys.ErrnoTransient, err.Error()), nil
	}
	return sys.Result(result), nil
}

func (d *Handler) Capabilities() []sys.Capability {
	return d.capabilities
}

func (d *Handler) Handles(name string) bool {
	_, ok := d.tools[name]
	return ok
}

func actionName(serverID, toolName string) string {
	replacer := strings.NewReplacer(" ", "_", "/", "_", ":", "_")
	return "mcp." + replacer.Replace(serverID) + "." + replacer.Replace(toolName)
}

type transport struct {
	config ServerConfig
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Scanner
	mu     sync.Mutex
	nextID int64
}

func start(ctx context.Context, config ServerConfig) (*transport, error) {
	cmd := exec.CommandContext(ctx, config.Command, config.Args...)
	cmd.Dir = config.Dir
	cmd.Env = append([]string(nil), os.Environ()...)
	for key, value := range config.Env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	s := &transport{config: config, cmd: cmd, stdin: stdin, stdout: scanner}
	if _, err := s.request(ctx, "initialize", map[string]any{
		"protocolVersion": ProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]string{"name": "aurora", "version": "1"},
	}); err != nil {
		_ = s.Close()
		return nil, err
	}
	if err := s.notify("notifications/initialized", map[string]any{}); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func (s *transport) listTools(ctx context.Context) ([]Tool, error) {
	raw, err := s.request(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var result struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return result.Tools, nil
}

func (s *transport) callTool(ctx context.Context, name string, arguments any) (json.RawMessage, error) {
	return s.request(ctx, "tools/call", map[string]any{"name": name, "arguments": arguments})
}

func (s *transport) request(ctx context.Context, method string, params any) (json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	request := map[string]any{
		"jsonrpc": "2.0", "id": s.nextID, "method": method, "params": params,
	}
	if err := writeJSONLine(s.stdin, request); err != nil {
		return nil, err
	}
	type response struct {
		ID     int64           `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !s.stdout.Scan() {
			if err := s.stdout.Err(); err != nil {
				return nil, err
			}
			return nil, io.ErrUnexpectedEOF
		}
		var decoded response
		if err := json.Unmarshal(s.stdout.Bytes(), &decoded); err != nil {
			return nil, fmt.Errorf("decode MCP response: %w", err)
		}
		if decoded.ID != s.nextID {
			continue
		}
		if decoded.Error != nil {
			return nil, fmt.Errorf("MCP error %d: %s", decoded.Error.Code, decoded.Error.Message)
		}
		return append(json.RawMessage(nil), decoded.Result...), nil
	}
}

func (s *transport) notify(method string, params any) error {
	return writeJSONLine(s.stdin, map[string]any{
		"jsonrpc": "2.0", "method": method, "params": params,
	})
}

func (s *transport) Close() error {
	if s == nil {
		return nil
	}
	_ = s.stdin.Close()
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	return s.cmd.Wait()
}

func writeJSONLine(writer io.Writer, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	_, err = writer.Write(raw)
	return err
}
