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
  owns its name (internet requests, injected handlers).
- `internet`: bounded allowlisted HTTP client for requests of **any** method.
  The grant's `permissions` — `{methods, domain}` pairs, where `methods` may be
  `["*"]` and `domain` may be `"*"` — are the policy that constrains every
  request the program can make (checked at dispatch and on every redirect hop);
  request and response bodies are size-bounded.
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

Remaining domain driver modules live separately (`-k8s`, `-helm`) so an
assembly pulls only the clients it ships; `aurora-dispatchers-llm` folded in
here as `openaillm`.
