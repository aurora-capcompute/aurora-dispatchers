# aurora-dispatchers

Reusable host-side dispatcher implementations for Aurora and other
`capcompute` applications.

This project owns concrete external-I/O clients, their configuration, and
capability schemas. Durable runs, journals, webhook tasks, and Wasm sessions
remain owned by Aurora.

Packages:

- `builtin`: capability dispatcher for LLM, internet, and registered MCP tools.
- `internet`: bounded allowlisted HTTP GET client.
- `llm`: fake and OpenAI-compatible chat clients.
- `mcp`: stdio MCP discovery and tool calls.
- `resolution`: context passed to a dispatcher after Aurora resolves a
  webhook task.
