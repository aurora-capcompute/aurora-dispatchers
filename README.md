# aurora-dispatchers

Reusable capability drivers for `capcompute` assemblies: concrete external-I/O
clients, their configuration, and the capability schemas they publish. Every
driver speaks the kernel's `sys` vocabulary (`sys.Dispatcher`, `sys.Syscall`,
`sys.SyscallResult` with errno-classified failures) and yields for approval by
returning `sys.Yield` until the dispatch carries an approved
`sys.Authorization`.

Durable runs, journals, approval tasks, and guest processes are owned by the
runtime (`aurora-capcompute`); channels and control planes by the assembly.
This module is drivers only.

Packages:

- `builtin`: the leaf dispatcher — routes each syscall to the handler that
  owns its name (internet reads, registered MCP tools, injected handlers).
- `internet`: bounded allowlisted HTTP GET client.
- `mcp`: stdio MCP discovery and tool calls.
- `memory`: the `core.memory` tenant-scoped shared store capability —
  subtree-chrooted grants, approval-gated writes, provenance-preserving
  (values re-surface with the taint they were written under). The durable
  `memory.Store` behind it is injected.
- `registry`: assembles built-in drivers and their capability schemas from
  tool entries.
- `timer`: the `timer.set` durable-wait capability.

Domain driver modules live separately (`aurora-dispatchers-llm`, `-k8s`,
`-helm`) so an assembly pulls only the clients it ships.
