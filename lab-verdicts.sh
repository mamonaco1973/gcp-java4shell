#!/bin/bash
set -euo pipefail

# ================================================================================
# lab-verdicts.sh — report each node's live CVE-2026-114938 verdict
#
# Usage:
#   ./lab-verdicts.sh                 # all three nodes
#   ./lab-verdicts.sh vuln-x86          # one (or several) named nodes
#
# For each node it runs the on-box /opt/java4shell/exposure-check.sh over SSM
# Run Command and prints the result. This is only the operator fan-out: the
# verdict comes from the portable check-exposure.sh detector on each node.
# Nothing is reached over the network — everything goes through the SSM agent's
# outbound channel.
# ================================================================================

CHDIR="01-java4shell"
POLL=10
TIMEOUT=300

REGION=$(terraform -chdir="$CHDIR" output -raw region 2>/dev/null || true)
if [ -z "${REGION}" ]; then
  echo "ERROR: could not read Terraform outputs. Run ./apply.sh first."
  exit 1
fi

NODE_IDS_JSON=$(terraform -chdir="$CHDIR" output -json node_ids)

# Roles to check: args if given, else all keys in the output (stable order).
if [ "$#" -gt 0 ]; then
  ROLES=("$@")
else
  mapfile -t ROLES < <(echo "${NODE_IDS_JSON}" | jq -r 'keys_unsorted[]')
fi

# Wait until an instance is a registered, Online SSM managed node.
wait_online() {
  local id="$1" elapsed=0 status
  while true; do
    status=$(aws ssm describe-instance-information --region "${REGION}" \
      --filters "Key=InstanceIds,Values=${id}" \
      --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null || echo "None")
    [ "${status}" = "Online" ] && return 0
    elapsed=$((elapsed + POLL))
    [ "${elapsed}" -ge "${TIMEOUT}" ] && return 1
    sleep "${POLL}"
  done
}

# Run a command on an instance via SSM and echo its stdout.
run_onbox() {
  local id="$1" cmd="$2" cid params
  params=$(jq -nc --arg c "${cmd}" '{commands:[$c]}')
  cid=$(aws ssm send-command --region "${REGION}" --instance-ids "${id}" \
    --document-name "AWS-RunShellScript" --parameters "${params}" \
    --query 'Command.CommandId' --output text)
  aws ssm wait command-executed --region "${REGION}" \
    --command-id "${cid}" --instance-id "${id}" >/dev/null 2>&1 || true
  aws ssm get-command-invocation --region "${REGION}" \
    --command-id "${cid}" --instance-id "${id}" \
    --query 'StandardOutputContent' --output text
}

printf '\n%-14s %-12s %-10s %-6s %-6s %s\n' "NODE" "VERDICT" "JAVA" "ARCH" "VBMI" "REASON"
printf -- '---------------------------------------------------------------------------------------\n'

rc=0
for role in "${ROLES[@]}"; do
  id=$(echo "${NODE_IDS_JSON}" | jq -r --arg r "${role}" '.[$r] // empty')
  if [ -z "${id}" ]; then
    printf '%-14s %s\n' "${role}" "ERROR: unknown node (not in this deployment)"
    rc=1
    continue
  fi

  if ! wait_online "${id}"; then
    printf '%-14s %s\n' "${role}" "ERROR: not SSM-online after ${TIMEOUT}s (${id})"
    rc=1
    continue
  fi

  out=$(run_onbox "${id}" "/opt/java4shell/exposure-check.sh")
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
