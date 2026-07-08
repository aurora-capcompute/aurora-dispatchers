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
- `internet`: bounded allowlisted HTTP client for requests of **any** method,
  publishing the single `core.internet` capability. The grant's `capabilities`
  list — `{methods, domain}` entries, where `methods` may be `["*"]` and
  `domain` may be `"*"`, each optionally carrying its own `labels`/`taints`/
  `require_approval` — is the policy that constrains every request the program
  can make (checked at dispatch and on every redirect hop); the program selects
  one with the `method` field inside the call args, and request and response
  bodies are size-bounded.
- `memory`: the `core.memory` tenant-scoped shared store capability — a single
  capability whose `get`/`put` operations are selected by the `operation` field
  in the call args, with subtree-chrooted grants, per-operation approval gating,
  and provenance preservation (values re-surface with the taint they were
  written under). The durable `memory.Store` behind it is injected.
- `openaillm`: the `core.openaiApi` cognition tool — the standard LLM driver.
  It publishes a single `core.openaiApi` capability whose operations —
  `chat` / `responses` / `embeddings` / `models.list`, selected by an
  `operation` discriminator inside the call args — run against any
  OpenAI-compatible provider (base URL, key, and default model flattened onto
  the grant; each granted operation carries its own approval policy). Registered
  explicitly — `registry.New(..., openaillm.Registration{})` — since
  `registry.Default()` stays network-credential-free.
- `registry`: assembles built-in drivers and their capability schemas from
  tool entries.

Remaining domain driver modules live separately (`-k8s`, `-helm`) so an
assembly pulls only the clients it ships; `aurora-dispatchers-llm` folded in
here as `openaillm`.
