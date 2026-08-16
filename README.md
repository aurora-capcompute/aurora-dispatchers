# aurora-dispatchers

**The "device drivers" that let a sandboxed agent touch the real world — safely.**
`aurora-dispatchers` is a Go library of ready‑made capability drivers for Aurora:
make an HTTP call, read a file, get/put shared memory, or call an LLM. Each driver
runs the action *for* the agent, under a scoped, approval‑gated, recorded grant.

> New here? The first two sections explain what a "dispatcher" is and where it fits.
> Then see [Quick start](#quick-start-5-minutes) and the
> [assembly example](#example-assembling-a-dispatcher).

---

## What is this, in plain words?

An Aurora agent is a Wasm program with **zero ambient authority** — it can't open a
socket, read a file, or call an API by itself. Instead it emits a **syscall**
("please GET https://example.com"), and the matching **dispatcher** performs that
action on its behalf — but only within the limits of a **grant** you wrote in the
agent's manifest.

Every dispatcher in this repo enforces the same three safety mechanisms:

1. **Least privilege** — a grant scopes exactly what's allowed (which domains,
   which files, which operations). Anything outside it is denied.
2. **Approval gating** — mark a grant `require_approval: true` and the driver
   *yields* ("Approve this?") instead of acting, until a human says yes.
3. **Data‑flow tracking** — results are stamped with provenance **labels**, and a
   driver refuses a call whose inputs are too "tainted" to flow into that action.

This module is **drivers only**. The durable processes, journal, approval tasks,
and guest instances are owned by the runtime
([aurora-capcompute](https://github.com/aurora-capcompute/aurora-capcompute)).

## Where this fits in the Aurora system

```
        you (a human)
              │
   aurora-cli / aurora-slack-connector      ← clients you talk to
              │  HTTP /v1
         aurora-dist                         ← the server (one binary you run)
              │  assembled from…
   ┌──────────┴──────────┐
 aurora-capcompute    aurora-dispatchers     ← orchestration runtime + capability drivers
                      ◀ YOU ARE HERE
   └──────────┬──────────┘
              │  both built on
         capcompute                          ← the kernel (the foundation)

   aurora-brains  →  Wasm agent programs that emit the syscalls
```

An assembly (like [aurora-dist](https://github.com/aurora-capcompute/aurora-dist))
builds a `registry.Registry` from these drivers, calls `Registry.Build(...)` with a
tenant's granted syscalls, and hands the resulting dispatcher to the runtime. The
runtime then feeds each agent syscall to that dispatcher — journaling, approving,
and replaying around it.

## The drivers (features)

| Capability | Package | What it does | Key safety limits |
| --- | --- | --- | --- |
| `core.internet` | `internet/` | Bounded HTTP client, any method | Allowlist of `METHOD:origin`; **SSRF guard** blocks loopback/private/metadata IPs (post‑DNS, defeats rebinding); size + time bounds; policy re‑checked on every redirect |
| `core.filesystem` | `filesystem/` | **Read‑only** host‑file reads | Chrooted to declared `roots`; rejects symlink escapes; whole‑file or 1‑based line range; byte/line caps; optional extension allowlist; returns a SHA‑256 hash |
| `core.scratch` | `scratch/` | Process‑local *ephemeral* store | `get`/`put`/`list`/`search` on a single **unscoped** fresh, private store per process — cleared when it ends (a place to offload a large read out of the model's context); optimistic concurrency (`if_version`); **exactly‑once puts** via idempotency key; preserves provenance labels |
| `core.openaiApi` | `openaillm/` | The LLM driver — any OpenAI‑compatible provider | `chat`/`responses`/`embeddings`/`models`; base URL + key + model on the grant; model allowlist; refuses `stream:true`; usually `Hidden` from the agent's menu |
| `core.httpTemplate` | `httptemplate/` | Manifest‑fixed HTTP requests the agent only fills in | The agent fills declared `{{param}}` holes (percent‑ or JSON‑encoded) — it can't rewrite the URL or method |
| `core.command` | `command/` | Host commands from an author‑declared allowlist | One operation per allowlisted command; no shell (exec with a fixed argv); every slot is a closed set or an anchored pattern; no value may begin with `-` or carry a control character; the child inherits no environment; approval on by default |

Two shared mechanisms make grants expressive and safe:

- **Discriminated‑union capabilities** — one capability name per syscall; its
  multiple operations are selected by an `"operation"` (or HTTP `"method"`)
  discriminator *inside the args*, never by inventing new names.
- **Host‑held secrets** — a grant references a secret by name (`{"secret":"OPENAI_KEY"}`);
  the value is resolved host‑side and never enters the manifest, journal, or guest.

## Quick start (5 minutes)

This is a **library** — there's no binary to run. "Setup" is building and testing it.

**Prerequisites:** Go 1.26+.

```sh
git clone https://github.com/aurora-capcompute/aurora-dispatchers
cd aurora-dispatchers

go build ./...
go test ./...          # every driver, plus registry
go vet ./...
```

The tests double as worked examples — read `registry/build_test.go`,
`openaillm/registration_test.go`, `internet/registration_test.go`, and
`command/registration_test.go`.

## Example: assembling a table

You pick which registrations to include, then `Build` the grant table for one
process. Nothing registers itself — there is no global `init()`.

```go
reg := registry.New(
    internet.Registration{},
    filesystem.Registration{},
    scratch.Registration{},
    command.Registration{},
    httptemplate.Registration{},
    openaillm.Registration{},  // carries credentials, so include it deliberately
)

services := registry.Services{
    Secrets:  mySecretResolver, // resolves {"secret":"OPENAI_KEY"} host-side
    AuditKey: auditKey,         // keys the credential fingerprints on results
}

table, err := reg.Build(ctx, []registry.Entry{
    {Syscall: "core.internet",
     Config: json.RawMessage(`{"capabilities":[{"methods":["GET"],"domain":"example.com"}]}`)},
    {Syscall: "core.scratch",
     Config: json.RawMessage(`{"capabilities":[{"operation":"get"},{"operation":"put"}]}`)},
    {Syscall: "core.openaiApi", Hidden: true,
     Config: json.RawMessage(`{"api_key":{"secret":"OPENAI_KEY"},"default_model":"gpt-4o","capabilities":[{"operation":"chat"}]}`)},
}, services)
```

The table is the grant: the runtime routes with `capability.NewDispatcher(table)`
and its reference monitor judges every call against the same index.

## Configuration

There are no env vars read directly here — config arrives as JSON grant configs
plus an injected `registry.Services`. Highlights per driver:

- **openaillm** — `base_url` (default `https://api.openai.com/v1`), `api_key`
  (literal or `{"secret":"NAME"}`), `default_model`, `allowed_models`, `timeout`
  (2m), `max_request_bytes`, `headers` (Authorization/Host forbidden). The OpenAI
  SDK is built with explicit options so stray `OPENAI_*` env vars can't override a
  configured provider.
- **internet** — `capabilities[]{methods, domain, require_approval, inject_headers,
  labels, taints}`, `timeout_ms`, `max_response_bytes`, `allow_private_network`.
- **filesystem** — `roots[]` (required, existing absolute dirs), `extensions[]`,
  `max_read_bytes` (2 MiB), `max_lines` (10000), `follow_symlinks`.
- **memory** — `capabilities[]` is a list of **mounts**, each
  `{scope, space, operations[], require_approval, labels, taints}`; `scope` ∈
  `process` / `session` / `shared` (there is no tenant‑wide scope), and `space`
  names the shared space — required exactly when `scope` is `shared`, forbidden
  otherwise (the tag and its payload are separate fields, never packed into one
  string). Each call names its `scope` (+`space` for shared; omittable only when
  one mount is granted) and a `key`; the tenant + scope prefix are host‑set, so a
  key can never cross a tenant, and crosses a session only through a named shared
  space. `Services` must carry the calling `SessionID`/`ProcessID` for the
  self‑scopes to resolve.
- **scratch** — `capabilities[]{operation, require_approval, labels, taints}` — a
  single unscoped, process‑private store (no scope selector).
- **httptemplate** — `base_url` (grant default), `capabilities[]{operation, method,
  base_url, path, query, body, params, inject_headers, require_approval}`, bounds.

## Project layout

```
internet/      core.internet: bounded, allowlisted HTTP client + SSRF guard
filesystem/    core.filesystem: read-only, chrooted file reads
command/       core.command: host commands from an allowlist, one operation each
httptemplate/  core.httpTemplate: manifest-fixed requests the agent only fills in
scratch/       core.scratch: process-local ephemeral KV
memory/        the KV engine scratch is built on (MapStore is the reference impl)
openaillm/     core.openaiApi: the LLM driver (client / handler / settings)
registry/      the Registration interface + Registry.Build, the grant vocabulary
               (adt.go) and secret resolution (secret.go) — depends on no driver
```

## Dependencies

Only two direct dependencies: `github.com/aurora-capcompute/capcompute` (the `sys`
vocabulary every driver speaks) and `github.com/openai/openai-go/v3` (used only by
`openaillm`). Domain drivers live in their own modules so an assembly pulls only
the clients it ships.

## Related repos

- [capcompute](https://github.com/aurora-capcompute/capcompute) — the kernel whose `sys` vocabulary these drivers speak
- [aurora-capcompute](https://github.com/aurora-capcompute/aurora-capcompute) — the runtime that drives these dispatchers
- [aurora-dist](https://github.com/aurora-capcompute/aurora-dist) — the assembly that wires them into a server
- [aurora-brains](https://github.com/aurora-capcompute/aurora-brains) — the agent programs that emit the syscalls
