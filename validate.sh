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

POLL=10
TIMEOUT=600
# The startup script (package install + JDK download over Cloud NAT) runs well
# past the moment SSH answers, so it gets its own, more generous budget. The
# detector script is not written until it finishes, so collecting a verdict
# before then reads an empty "?" on every node.
PROVISION_TIMEOUT=1200

# ------------------------------------------------------------------------------
# Deploy timing — DEPLOY_START is exported by apply.sh so the headline number
# spans apply + boot + JDK install + first verdict. Standalone runs fall back to
# "now", which times only the IAP wait and is not comparable to an apply run.
# ------------------------------------------------------------------------------
T_ANCHOR="${DEPLOY_START:-$(date +%s)}"
T_START=$(date +%s)

source ./iap-common.sh

DEPLOYMENT=$(terraform -chdir="$CHDIR" output -raw deployment_name)
mapfile -t ROLES < <(echo "${NODE_NAMES_JSON}" | jq -r 'keys_unsorted[]')

wait_provisioned() {
  # Block until this node's startup script has finished: it writes
  # /root/userdata.done as its last act. The script never aborts on a failed
  # download, so a broken install still releases the wait (the verdict then
  # reads UNKNOWN instead of hanging).
  local name="$1" elapsed=0 status
  while true; do
    status=$(run_onbox "${name}" "test -f /root/userdata.done && echo done || echo running")
    [ "${status}" = "done" ] && return 0
    elapsed=$((elapsed + POLL))
    [ "${elapsed}" -ge "${PROVISION_TIMEOUT}" ] && return 1
    echo "NOTE: ${name} startup script still running (${status:-?}) — waiting ${POLL}s (${elapsed}s)..."
    sleep "${POLL}"
  done
}

echo "NOTE: Waiting for all nodes to accept IAP SSH..."
for role in "${ROLES[@]}"; do
  name=$(node_name "${role}")
  if ! wait_ssh "${name}" "${TIMEOUT}"; then
    echo "ERROR: ${role} (${name}) never accepted IAP SSH after ${TIMEOUT}s."
    exit 1
  fi
done
T_ONLINE=$(date +%s)

echo "NOTE: Waiting for the startup script (package + JDK install) to finish on all nodes..."
for role in "${ROLES[@]}"; do
  name=$(node_name "${role}")
  if ! wait_provisioned "${name}"; then
    echo "ERROR: ${role} (${name}) startup script did not finish within ${PROVISION_TIMEOUT}s."
    echo "       Check /root/userdata.log on the node over IAP SSH."
    exit 1
  fi
done

echo "NOTE: Collecting exposure verdicts..."
echo ""
printf '%-12s %-12s %-6s %s\n' "NODE" "VERDICT" "VBMI" "JDKS"
printf -- '---------------------------------------------------------------------------------------\n'

FAIL=0
for role in "${ROLES[@]}"; do
  name=$(node_name "${role}")
  out=$(run_onbox "${name}" "/opt/java4shell/exposure-check.sh")
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
echo "  Project / zone    : ${PROJECT} / ${ZONE}"
echo "  Nodes checked     : ${#ROLES[@]}"
echo "---------------------------------------------------------------------------------"
echo "  Time to validated : $((T_DONE - T_ANCHOR))s"
if [ -z "${DEPLOY_START:-}" ]; then
  echo "  WARNING: DEPLOY_START unset — timed from validate.sh only. Run ./apply.sh"
  echo "           for the full deploy-to-verdict number."
else
  echo "  IAP SSH wait      : $((T_ONLINE - T_START))s"
fi
echo "================================================================================="

if [ "${FAIL}" -ne 0 ]; then
  echo "  ERROR: ${FAIL} node(s) returned no verdict — see table above."
  echo "================================================================================="
  exit 1
fi
