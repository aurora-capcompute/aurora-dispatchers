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
# Install it somewhere the agent cannot write, and grant it as:
#
#   {"syscall":"core.command","capabilities":[{"operation":"run","commands":[{
#     "name":"kubectl-get",
#     "description":"List Kubernetes objects in a cluster",
#     "path":"/bin/bash",
#     "args":["/opt/aurora/bin/kubectl-get.sh","{context}","{resource}","{namespace}"],
#     "env":{"KUBECONFIG":"/etc/aurora/kubeconfig","PATH":"/usr/bin:/bin"},
#     "params":{
#       "context":["prod-eu","staging"],
#       "resource":"[a-z][a-z0-9]*",
#       "namespace":"[a-z0-9]([a-z0-9-]*[a-z0-9])?"
#     },
#     "timeout_ms":10000,
#     "require_approval":false,
#     "labels":["k8s"]
#   }]}]}
#
# The agent then calls:
#   {"operation":"run","name":"kubectl-get",
#    "params":{"context":"staging","resource":"pods","namespace":"default"}}

set -euo pipefail

if [[ $# -ne 3 ]]; then
	echo "usage: kubectl-get.sh <context> <resource> <namespace>" >&2
	exit 2
fi

context=$1
resource=$2
namespace=$3

# The verb is fixed here, not passed in: a caller that could choose it could
# choose "delete". The "--" stops kubectl reading any later argument as a flag,
# which is belt-and-braces given the driver already refuses a leading dash.
exec kubectl \
	--context="$context" \
	--namespace="$namespace" \
	--request-timeout=8s \
	get \
	-o json \
	-- "$resource"
