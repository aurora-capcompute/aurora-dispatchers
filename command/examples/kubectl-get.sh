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
# Grant the RESOURCE as a closed set, not a pattern. A pattern like
# "[a-z][a-z0-9]*" reads like "a resource name" and is one, but it also admits
# "secrets" — and `kubectl get secrets -o json` returns every value, base64 but
# not encrypted. The native core.kubernetes driver refuses Secret bodies outright;
# this driver cannot know that a given script talks to Kubernetes at all, so the
# choice has to be made here. DENIED_RESOURCES below is the second line of
# defence, in case a grant is later widened without this file being reread.
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
#       "resource":["pods","deployments","services","configmaps","nodes","events"],
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

# Resources whose bodies carry credentials. Refused here regardless of what the
# grant admits, so widening the manifest cannot quietly turn a read of workloads
# into a dump of every secret in the namespace.
DENIED_RESOURCES="secrets serviceaccounts"

if [[ $# -ne 3 ]]; then
	echo "usage: kubectl-get.sh <context> <resource> <namespace>" >&2
	exit 2
fi

context=$1
resource=$2
namespace=$3

for denied in $DENIED_RESOURCES; do
	if [[ $resource == "$denied" ]]; then
		echo "refusing to read ${resource}: its contents are credentials" >&2
		exit 3
	fi
done

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
