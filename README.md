# aurora-dispatchers

Reusable capability drivers for `capcompute` assemblies: concrete external-I/O
clients, their configuration, and the capability schemas they publish. Every
driver speaks the kernel's `sys` vocabulary (`sys.Dispatcher`, `sys.Syscall`,
`sys.SyscallResult` with errno-classified failures) and yields for approval by
returning `sys.Yield` until the dispatch carries an approved
`sys.Authorization`.

Durable processes, journals, approval tasks, and guest instances are owned by
the runtime (`aurora-capcompute`); channels and control planes by the assembly.
This module is drivers only.

Packages:

- `builtin`: the leaf dispatcher — routes each syscall to the handler that
  owns its name (internet reads, registered MCP tools, injected handlers).
- `hold`: the `core.hold` reference Try-Confirm/Cancel reservation capability —
  saga isolation as explicitly pending holds (`reserve` → `confirm`, or
  `release`/expiry) over a process-local hold table; `reserve` is exactly-once
  under the kernel's idempotency keys, `release` is the natural
  `sys.compensate` target.
- `internet`: bounded allowlisted HTTP GET client.
- `mcp`: stdio MCP discovery and tool calls.
- `memory`: the `core.memory` tenant-scoped shared store capability —
  subtree-chrooted grants, approval-gated writes, provenance-preserving
  (values re-surface with the taint they were written under). The durable
  `memory.Store` behind it is injected.
- `openaillm`: the `core.openaiApi` cognition tool — the standard LLM driver.
  It publishes the fixed `openai.chat` / `openai.responses` /
  `openai.embeddings` / `openai.models.list` operations against any
  OpenAI-compatible provider (base URL, key, model allowlist, and approval
  policy set per grant). Registered explicitly — `registry.New(...,
  openaillm.Registration{})` — since `registry.Default()` stays
  network-credential-free.
- `registry`: assembles built-in drivers and their capability schemas from
  tool entries.
- `timer`: the `timer.set` durable-wait capability.

Remaining domain driver modules live separately (`-k8s`, `-helm`) so an
assembly pulls only the clients it ships; `aurora-dispatchers-llm` folded in
here as `openaillm`.
