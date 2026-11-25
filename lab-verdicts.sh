#!/bin/bash
set -euo pipefail

# ================================================================================
# lab-verdicts.sh — report each node's live CVE-2026-114938 verdict
#
# Usage:
#   ./lab-verdicts.sh                 # all three nodes
#   ./lab-verdicts.sh vuln-x86        # one (or several) named nodes
#
# For each node it runs the on-box /opt/java4shell/exposure-check.sh over
# IAP-tunnelled SSH and prints the result. This is only the operator fan-out:
# the verdict comes from the portable check-exposure.sh detector on each node.
# The nodes have no external IP — everything goes through Google's IAP proxy.
# ================================================================================

TIMEOUT=300
source ./iap-common.sh

# Roles to check: args if given, else all keys in the output (stable order).
if [ "$#" -gt 0 ]; then
  ROLES=("$@")
else
  mapfile -t ROLES < <(echo "${NODE_NAMES_JSON}" | jq -r 'keys_unsorted[]')
fi

printf '\n%-14s %-12s %-10s %-6s %-6s %s\n' "NODE" "VERDICT" "JAVA" "ARCH" "VBMI" "REASON"
printf -- '---------------------------------------------------------------------------------------\n'

rc=0
for role in "${ROLES[@]}"; do
  name=$(node_name "${role}")
  if [ -z "${name}" ]; then
    printf '%-14s %s\n' "${role}" "ERROR: unknown node (not in this deployment)"
    rc=1
    continue
  fi

  if ! QUIET_WAIT=1 wait_ssh "${name}" "${TIMEOUT}"; then
    printf '%-14s %s\n' "${role}" "ERROR: not reachable over IAP SSH after ${TIMEOUT}s (${name})"
    rc=1
    continue
  fi

  out=$(run_onbox "${name}" "/opt/java4shell/exposure-check.sh" || true)
  verdict=$(echo "${out}" | sed -n 's/^VERDICT=//p')
  java=$(echo "${out}"    | sed -n 's/^JAVA_VERSION=//p')
  arch=$(echo "${out}"    | sed -n 's/^ARCH=//p')
  vbmi=$(echo "${out}"    | sed -n 's/^AVX512_VBMI=//p')
  reason=$(echo "${out}"  | sed -n 's/^REASON=//p')

  printf '%-14s %-12s %-10s %-6s %-6s %s\n' \
    "${role}" "${verdict:-?}" "${java:-?}" "${arch:-?}" "${vbmi:-?}" "${reason:-?}"

  # Per-JDK breakdown: JVM|installed|<home>|<version>|<verdict>|<reason>
  echo "${out}" | sed -n 's/^JVM|installed|[^|]*|\([^|]*\)|\([^|]*\)|.*/                 \1  ->  \2/p'
done

echo ""
exit "${rc}"
