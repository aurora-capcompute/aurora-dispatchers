#!/usr/bin/env bash
#
# kubectl-get.sh — the host half of a core.command grant that lets an agent read
# Kubernetes objects.
#
# The driver guarantees a great deal before this script runs: there is no shell
# between it and the caller, so $1..$3 arrive as exactly the argv elements the
# driver built; none of them can begin with "-" or contain a control character;
# and each has already matched the closed set or anchored pattern its slot
# declared. What this script must still get right is its own quoting, and the
# fact that it — not the manifest, and certainly not the agent — decides that the
# verb is "get".
#
# TWO POSTURES
#
# If the agent only needs a few resource types, grant `resource` as a closed set
# and you are done:
#
#     "resource":["pods","deployments","services","configmaps","nodes","events"]
#
# If it needs to read broadly — an admin context, an assistant that explores —
# grant `resource` as a pattern and rely on the Secret filter below. Note what
# that costs: with a read-everything credential the API server's own RBAC is no
# longer a backstop, so this script is the entire boundary.
#
# WHY THE FILTER LOOKS AT THE ANSWER, NOT THE REQUEST
#
# Refusing the string "secrets" does not work. kubectl accepts the singular, the
# short name, and the fully-qualified form, so "secret", "sa" and "secrets.v1."
# all reach the same objects while defeating any request-side deny list. What
# comes back, however, always says "kind":"Secret" — whatever it was asked for.
# So the filter reads the response: every Secret keeps its name, namespace,
# labels and timestamps, and loses .data and .stringData. The agent can see that
# a Secret exists and what it is called; it cannot read the bytes.
#
#   {"syscall":"core.command","capabilities":[{"operation":"run","commands":[{
#     "name":"kubectl-get",
#     "description":"Read Kubernetes objects (Secret values are withheld)",
#     "path":"/bin/bash",
#     "args":["/opt/aurora/bin/kubectl-get.sh","{context}","{resource}","{namespace}"],
#     "env":{"KUBECONFIG":"/etc/aurora/kubeconfig","PATH":"/usr/bin:/bin"},
#     "params":{
#       "context":["prod-eu","staging"],
#       "resource":"[a-z][a-z0-9.-]*",
#       "namespace":"[a-z0-9]([a-z0-9-]*[a-z0-9])?"
#     },
#     "timeout_ms":10000,
#     "require_approval":false,
#     "labels":["k8s","cluster_read"]
#   }]}]}
#
# And label the read, as above. `cluster_read` on this grant, listed in the
# `taints` of every capability that can reach the outside world, is what stops
# something read here from being sent somewhere else — the control that actually
# matters once the credential can read everything.

set -euo pipefail

if [[ $# -ne 3 ]]; then
	echo "usage: kubectl-get.sh <context> <resource> <namespace>" >&2
	exit 2
fi

context=$1
resource=$2
namespace=$3

# Fail closed: without jq the Secret filter cannot run, and passing the raw
# answer through would be exactly the leak this script exists to prevent.
if ! command -v jq >/dev/null 2>&1; then
	echo "jq is required to withhold Secret values; refusing to read without it" >&2
	exit 4
fi

# The verb is fixed here, not passed in: a caller that could choose it could
# choose "delete". The "--" stops kubectl reading any later argument as a flag,
# which is belt-and-braces given the driver already refuses a leading dash.
answer=$(kubectl \
	--context="$context" \
	--namespace="$namespace" \
	--request-timeout=8s \
	get \
	-o json \
	-- "$resource")

# Strip the credential-bearing fields from anything that came back as a Secret,
# whether it arrived as a single object or inside a List. Everything else passes
# through untouched.
printf '%s' "$answer" | jq '
  def redact:
    if .kind == "Secret"
    then del(.data, .stringData) + {aurora_note: "Secret values withheld by policy"}
    else . end;
  if .items then .items |= map(redact) else redact end
'
