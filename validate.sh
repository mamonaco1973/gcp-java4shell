#!/bin/bash
# ===============================================================================
# File: validate.sh
# Confirms the lab deployed as intended: each node's LIVE exposure verdict must
# match the verdict it was designed to produce (locals.tf -> node_expected).
# Every node carries all three affected trains (17 / 21 / 25); the per-JDK rows
# below each node show the detector judged every one.
#   vuln-x86     EXPOSED       (3 vulnerable JDKs + AVX-512 VBMI CPU)
#   safe-arm     NOT_EXPOSED   (same 3 JDKs, but ARM64 has no VBMI intrinsic)
#   safe-intel   NOT_EXPOSED   (same 3 JDKs, but this Intel chip has no VBMI)
# ===============================================================================

set -uo pipefail

CHDIR="01-java4shell"
POLL=10
TIMEOUT=600
# Cloud-init (package install + JDK download over NAT) runs well past the moment
# the SSM agent reports Online, so it gets its own, more generous budget. The
# detector script is not written until user data finishes, so collecting a
# verdict before this completes reads an empty "?" on every node.
CLOUD_INIT_TIMEOUT=1200

# ------------------------------------------------------------------------------
# Deploy timing — DEPLOY_START is exported by apply.sh so the headline number
# spans apply + boot + JDK install + first verdict. Standalone runs fall back to
# "now", which times only the SSM wait and is not comparable to an apply run.
# ------------------------------------------------------------------------------
T_ANCHOR="${DEPLOY_START:-$(date +%s)}"
T_START=$(date +%s)

REGION=$(terraform -chdir="$CHDIR" output -raw region 2>/dev/null || true)
if [ -z "${REGION}" ]; then
  echo "ERROR: could not read Terraform outputs. Run ./apply.sh first."
  exit 1
fi

DEPLOYMENT=$(terraform -chdir="$CHDIR" output -raw deployment_name)
NODE_IDS_JSON=$(terraform -chdir="$CHDIR" output -json node_ids)
mapfile -t ROLES < <(echo "${NODE_IDS_JSON}" | jq -r 'keys_unsorted[]')

wait_online() {
  local id="$1" elapsed=0 status
  while true; do
    status=$(aws ssm describe-instance-information --region "${REGION}" \
      --filters "Key=InstanceIds,Values=${id}" \
      --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null || echo "None")
    [ "${status}" = "Online" ] && return 0
    elapsed=$((elapsed + POLL))
    [ "${elapsed}" -ge "${TIMEOUT}" ] && return 1
    echo "NOTE: ${id} not SSM-online yet — retrying in ${POLL}s (${elapsed}s)..."
    sleep "${POLL}"
  done
}

wait_cloudinit() {
  # Block until this node's user data has finished. SSM Online only means the
  # agent is up; the JDK install and the detector script land minutes later. We
  # poll `cloud-init status` rather than the script path so an install that ends
  # in error/degraded still releases the wait (the verdict then reflects that,
  # e.g. UNKNOWN, instead of hanging).
  local id="$1" elapsed=0 status
  while true; do
    status=$(run_onbox "${id}" "cloud-init status 2>/dev/null | sed -n 's/^status: //p'")
    case "${status}" in
      done|error|degraded|disabled) return 0 ;;
    esac
    elapsed=$((elapsed + POLL))
    [ "${elapsed}" -ge "${CLOUD_INIT_TIMEOUT}" ] && return 1
    echo "NOTE: ${id} user data still running (cloud-init: ${status:-?}) — waiting ${POLL}s (${elapsed}s)..."
    sleep "${POLL}"
  done
}

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

echo "NOTE: Waiting for all nodes to register with SSM..."
for role in "${ROLES[@]}"; do
  id=$(echo "${NODE_IDS_JSON}" | jq -r --arg r "${role}" '.[$r]')
  if ! wait_online "${id}"; then
    echo "ERROR: ${role} (${id}) never came online in SSM after ${TIMEOUT}s."
    exit 1
  fi
done
T_ONLINE=$(date +%s)

echo "NOTE: Waiting for user data (package + JDK install) to finish on all nodes..."
for role in "${ROLES[@]}"; do
  id=$(echo "${NODE_IDS_JSON}" | jq -r --arg r "${role}" '.[$r]')
  if ! wait_cloudinit "${id}"; then
    echo "ERROR: ${role} (${id}) user data did not finish within ${CLOUD_INIT_TIMEOUT}s."
    echo "       Check /root/userdata.log on the node over SSM."
    exit 1
  fi
done

echo "NOTE: Collecting exposure verdicts..."
echo ""
printf '%-12s %-12s %-6s %s\n' "NODE" "VERDICT" "VBMI" "JDKS"
printf -- '---------------------------------------------------------------------------------------\n'

FAIL=0
for role in "${ROLES[@]}"; do
  id=$(echo "${NODE_IDS_JSON}"  | jq -r --arg r "${role}" '.[$r]')
  out=$(run_onbox "${id}" "/opt/java4shell/exposure-check.sh")
  got=$(echo "${out}"   | sed -n 's/^VERDICT=//p')
  vbmi=$(echo "${out}"  | sed -n 's/^AVX512_VBMI=//p')
  count=$(echo "${out}" | sed -n 's/^JDK_COUNT=//p')

  # A blank or UNKNOWN verdict means the scan itself failed on that node.
  if [ -z "${got}" ] || [ "${got}" = "UNKNOWN" ]; then
    FAIL=$((FAIL + 1))
  fi
  printf '%-12s %-12s %-6s %s\n' \
    "${role}" "${got:-?}" "${vbmi:-?}" "${count:-?}"

  # Per-JDK breakdown — proves the detector judged every installed train.
  #   JVM|installed|<home>|<version>|<verdict>|<reason>
  echo "${out}" | sed -n 's/^JVM|installed|[^|]*|\([^|]*\)|\([^|]*\)|.*/                 \1  ->  \2/p'

  if [ "${got}" = "UNKNOWN" ]; then
    echo "      ^ JDK install failed on ${role}. A vulnerable Corretto build URL is likely"
    echo "        pulled. Check 'terraform -chdir=${CHDIR} output affected_jdks', confirm each"
    echo "        returns HTTP 200, or set corretto_affected_url_override."
  fi
done

T_DONE=$(date +%s)
echo ""
echo "================================================================================="
echo "  Java4Shell (CVE-2026-114938) — lab validation"
echo "================================================================================="
echo "  Deployment        : ${DEPLOYMENT}"
echo "  Region            : ${REGION}"
echo "  Nodes checked     : ${#ROLES[@]}"
echo "---------------------------------------------------------------------------------"
echo "  Time to validated : $((T_DONE - T_ANCHOR))s"
if [ -z "${DEPLOY_START:-}" ]; then
  echo "  WARNING: DEPLOY_START unset — timed from validate.sh only. Run ./apply.sh"
  echo "           for the full deploy-to-verdict number."
else
  echo "  SSM online wait   : $((T_ONLINE - T_START))s"
fi
echo "================================================================================="

if [ "${FAIL}" -ne 0 ]; then
  echo "  ERROR: ${FAIL} node(s) returned no verdict — see table above."
  echo "================================================================================="
  exit 1
fi
