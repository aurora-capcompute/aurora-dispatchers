# aurora-dispatchers

`aurora-dispatchers` is a Go library of capability drivers for Aurora. A driver
does one kind of work for an agent: an HTTP call, an allowlisted host command, a
session store, an LLM call. It works only inside the grant that the agent's
manifest states.

An Aurora agent is a Wasm program with no ambient authority. It cannot open a
socket or call an API. It sends a **syscall**, and the matching driver does the
work. Every grant has three controls:

1. **Least privilege.** The grant states exactly what is allowed (domains,
   commands, operations). The runtime denies everything else.
2. **Approval.** With `require_approval: true`, the call yields until a human
   approves it.
3. **Flow labels.** Results carry provenance labels (`labels`), and the runtime
   refuses a call when the process carries a label that the operation forbids
   (`taints`).

This module is drivers only. The runtime
([aurora-capcompute](https://github.com/aurora-capcompute/aurora-capcompute))
owns processes, the journal, approval tasks and the monitor. An assembly such as
[aurora-dist](https://github.com/aurora-capcompute/aurora-dist) builds a
`registry.Registry`, calls `Registry.Build` with a process's grants, and gives
the resulting table to the runtime.

## Drivers

| Capability | Package | What it does | Limits |
| --- | --- | --- | --- |
| `core.internet` | `internet/` | HTTP client, any method | Method and domain allowlist, checked again on every redirect. A dial guard refuses loopback, private, link-local and CGNAT addresses after DNS. Size and time bounds. Optional host-held credential, bound to one origin. |
| `core.httpTemplate` | `httptemplate/` | HTTP requests fixed in the manifest | The agent fills declared `{{param}}` slots. It cannot change the URL or the method. |
| `core.command` | `command/` | Host commands from an allowlist | See [Host commands](#host-commands). |
| `core.scratch` | `scratch/` | The session's durable key-value store | `get`, `put`, `store`, `list`, `search` on the calling session's store. `store` saves a value under `io/<hash>`, which never changes. Values keep the writer's labels. |
| `core.openaiApi` | `openaillm/` | Any OpenAI-compatible LLM | `chat`, `responses`, `embeddings`, `models`. Base URL, key and model in the grant. Model allowlist. No streaming. Usually `hidden` from the agent's menu. |

Each capability has one name. Its operations are cases selected by a field in
the arguments (`operation`, or `method` for `core.internet`), never by new
names. A grant names a secret as `{"secret":"NAME"}`. The host resolves the
value. It never enters the manifest, the journal or the guest.

## Host commands

The manifest author owns the whole command line. The agent only fills declared
slots. The driver enforces:

- an absolute executable, with no `PATH` lookup and no shell.
- slot values from a closed set or an anchored pattern, never starting with
  `-`, never with control characters.
- an absolute `dir`, stated in the rule.
- an environment that the rule declares, with nothing inherited.
- approval on by default, with the resolved command line, `dir` and env names
  in the prompt.
- the bounds: a timeout and a cap on output size.

A non-zero exit is a result with `exit_code`, `stdout` and `stderr`. The
program decides what it means.

The driver does **not** confine what the binary does after it starts. The binary
runs with the server's operating-system rights. The author vouches for every
allowed command and slot value. Some binaries read meaning into a value with no
dash: `curl -d @file` uploads a local file. Confine the server in its deployment
(a dedicated user, a container, egress rules), and give each command
least-privilege credentials in its `env`.

## Use

```go
reg := registry.New(
    internet.Registration{},
    scratch.Registration{Store: sessionStore}, // the calling session's store
    command.Registration{},
    httptemplate.Registration{},
    openaillm.Registration{},
)

table, err := reg.Build(ctx, []registry.Entry{
    {Syscall: "core.internet",
     Config: json.RawMessage(`{"capabilities":[{"methods":["GET"],"domain":"example.com"}]}`)},
    {Syscall: "core.openaiApi", Hidden: true,
     Config: json.RawMessage(`{"api_key":{"secret":"OPENAI_KEY"},"default_model":"gpt-4o","capabilities":[{"operation":"chat"}]}`)},
}, registry.Services{
    Secrets:  secretResolver, // resolves {"secret":"NAME"}
    AuditKey: auditKey,       // keys the credential fingerprints on results
})
```

Nothing registers itself. There is no global `init()`. The table is the grant:
the runtime routes with `capability.NewDispatcher(table)`, and its monitor
checks every call against the same table.

## Grant configuration

All configuration comes from the grant JSON and `registry.Services`. The module
reads no environment variables.

- **internet:** `capabilities[]{methods, domain, description, require_approval,
  inject_headers, labels, taints}`, `timeout_ms`, `max_response_bytes`,
  `max_request_bytes`, `allow_private_network`.
- **httptemplate:** `base_url`, `capabilities[]{operation, description, method,
  base_url, path, query, body, params, inject_headers, require_approval, labels,
  taints}`, `timeout_ms`, `max_response_bytes`, `max_request_bytes`,
  `allow_private_network`. A `params` entry is `{type, required, description,
  enum}`.
- **command:** `capabilities[]{operation, description, path, dir, args, env,
  params, timeout_ms, max_output_bytes, require_approval, labels, taints}`. A
  `params` value is a list (a closed set) or a string (a pattern that the
  driver anchors). An `env` value is a string or `{"secret":"NAME"}`.
- **scratch:** `capabilities[]{operation, require_approval, labels, taints}`. The
  host binds the store to the session. A grant cannot name another session.
- **openaillm:** `capabilities[]{operation, require_approval, labels, taints}`,
  `base_url` (default `https://api.openai.com/v1`), `api_key`
  (`{"secret":"NAME"}` only), `api_key_optional`, `default_model`,
  `allowed_models`, `organization`, `project`, `timeout` (2m), `max_retries`,
  `max_request_bytes`, `allow_insecure_http`, `headers` (no `Authorization`,
  `Host` or `Content-Length`). `allowed_models` also narrows the `model` field
  in the published schema, so the runtime refuses another model before any
  approval. Requests go through `core.internet`'s client, fixed to the
  provider's origin, so they share its dial guard and size bounds. A network
  error, a 429 or a 5xx is tried again up to `max_retries` times (default 2).

## Build and test

```sh
go build ./...
go vet ./...
go test ./...
```

The tests are also examples: `registry/build_test.go`,
`internet/registration_test.go`, `openaillm/registration_test.go`,
`command/registration_test.go`.

## Layout

```
internet/      core.internet: allowlisted HTTP client and dial guard
httptemplate/  core.httpTemplate: requests fixed in the manifest
command/       core.command: allowlisted host commands
scratch/       core.scratch: handler, Store contract, MapStore, registration
openaillm/     core.openaiApi: client, handler, settings
registry/      Registration, Registry.Build, the grant vocabulary, secrets
```

Direct dependencies: `capcompute` (the `sys` vocabulary) and
`aurora-capcompute` (the `capability` table). Everything else is the Go
standard library.
