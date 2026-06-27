# aurora-dispatchers

Reusable host-side dispatcher implementations for Aurora and other
`capcompute` applications.

This project owns concrete external-I/O clients, their configuration, and
capability schemas. Durable runs, journals, webhook tasks, and Wasm sessions
remain owned by Aurora.

Packages:

- `builtin`: capability dispatcher for internet reads, registered MCP tools, and
  injected capability handlers.
- `internet`: bounded allowlisted HTTP GET client.
- `mcp`: stdio MCP discovery and tool calls.
- `registry`: assembles the built-in dispatchers and their capability schemas.
- `timer`: the `timer.set` durable-wait capability.
- `resolution`: context passed to a dispatcher after Aurora resolves a
  webhook task.

LLM chat clients live in the separate `aurora-dispatchers-llm` module.
