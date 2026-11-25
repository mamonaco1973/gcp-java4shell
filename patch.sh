#!/bin/bash
set -uo pipefail

# ================================================================================
# patch.sh — remediate a node in place by upgrading its JDKs
# Every node carries all three affected trains (17 / 21 / 25). This script
# downloads each train's FIXED Corretto build over SSM, installs it, repoints the
# decoder's JDK symlink to the fixed decoder train, REMOVES the vulnerable builds
# (the detector scans every installed JDK, so a lingering vulnerable one keeps the
# host EXPOSED), restarts the decoder, and re-runs the on-box exposure check to
# confirm the verdict flips EXPOSED -> NOT_EXPOSED.
#
# Why an upgrade and not a flag:
#   The documented TEMPORARY workarounds for CVE-2026-114938 disable the
#   vulnerable AVX-512 Base64 intrinsic without changing the JDK:
#       -XX:+UnlockDiagnosticVMOptions -XX:-UseBASE64Intrinsics
#       -XX:UseAVX=2            (x86-only; keeps AVX2, drops AVX-512)
#   They are stopgaps — Oracle's guidance, and this script, apply the real fix:
#   the patched runtime.
#
# Usage:
#   ./patch.sh                       # patch every EXPOSED node, all three trains
#   ./patch.sh vuln-x86              # patch a named node, all three trains
#   ./patch.sh vuln-x86 17           # patch ONLY train 17 on vuln-x86 (demo a
#                                    #   mixed host: 17 fixed, 21/25 still EXPOSED)
#   ./patch.sh vuln-x86 17 25        # patch trains 17 and 25, leave 21 vulnerable
# ================================================================================

CHDIR="01-java4shell"
REGION=$(terraform -chdir="$CHDIR" output -raw region 2>/dev/null || true)
if [ -z "${REGION}" ]; then
  echo "ERROR: could not read Terraform outputs. Run ./apply.sh first."
  exit 1
fi

NODE_IDS=$(terraform -chdir="$CHDIR" output -json node_ids)
PATCH_JDKS=$(terraform -chdir="$CHDIR" output -json patch_jdks)
NODE_EXPECTED=$(terraform -chdir="$CHDIR" output -json node_expected)
DECODER_MAJOR=$(terraform -chdir="$CHDIR" output -raw decoder_major)

# Arg parsing: optional first arg is a role; any remaining args are train majors
# to restrict the patch to. With no role, patch every node the lab expects to be
# EXPOSED (there is nothing to flip on a CPU-immune node).
TRAINS=()
if [ "$#" -gt 0 ]; then
  ROLES=("$1"); shift
  TRAINS=("$@")
else
  mapfile -t ROLES < <(echo "${NODE_EXPECTED}" | jq -r 'to_entries[] | select(.value=="EXPOSED") | .key')
  if [ "${#ROLES[@]}" -eq 0 ]; then
    echo "NOTE: no node is expected EXPOSED; nothing to patch. Name a node to force it."
    exit 0
  fi
fi

# Run a command on an instance over SSM and echo its stdout.
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

patch_one() {
  local role="$1" id jq_filter jlist out new_verdict new_java

  id=$(echo "${NODE_IDS}" | jq -r --arg r "${role}" '.[$r] // empty')
  if [ -z "${id}" ]; then
    echo "ERROR: no node named '${role}' in this deployment."; return 1
  fi

  # "major url" lines for the fixed builds, optionally filtered to TRAINS.
  if [ "${#TRAINS[@]}" -gt 0 ]; then
    jq_filter=$(printf '%s\n' "${TRAINS[@]}" | jq -R . | jq -s 'map(tostring)')
    jlist=$(echo "${PATCH_JDKS}" | jq -r --arg r "${role}" --argjson keep "${jq_filter}" \
      '.[$r][] | select(.major as $m | $keep | index($m)) | "\(.major) \(.url)"')
  else
    jlist=$(echo "${PATCH_JDKS}" | jq -r --arg r "${role}" '.[$r][] | "\(.major) \(.url)"')
  fi
  if [ -z "${jlist}" ]; then
    echo "ERROR: '${role}' has no fixed builds matching trains: ${TRAINS[*]:-all}."
    return 1
  fi

  echo ""
  echo "NOTE: ${role} (${id}) — verdict BEFORE patch:"
  ./lab-verdicts.sh "${role}"

  # On-box remediation. JLIST and DECODER_MAJOR are expanded HERE by patch.sh;
  # everything else ($VAR) stays literal for the remote shell.
  #
  # NOTE: SSM AWS-RunShellScript runs this under /bin/sh (dash), not bash, so the
  # remote half must stay POSIX — no here-strings, mapfile, or [[ ]]. The JDK
  # list goes through a temp file (not `<<<`), which also keeps the loop in the
  # current shell so NEWDIRS survives for the prune step.
  local patch_cmd
  read -r -d '' patch_cmd <<PATCH || true
set -e
cd /tmp
DECODER_MAJOR="${DECODER_MAJOR}"
cat > /tmp/j4s_jlist.txt <<'JLIST_EOF'
${jlist}
JLIST_EOF
OLD=\$(ls -d /opt/amazon-corretto-* 2>/dev/null || true)
NEWDIRS=""
while read -r MAJOR URL; do
  [ -n "\$MAJOR" ] || continue
  echo "downloading fixed train \$MAJOR: \$URL"
  curl -fL --retry 20 --retry-delay 8 --retry-all-errors --retry-connrefused --connect-timeout 10 -o "fixed-\$MAJOR.tar.gz" "\$URL"
  TOP=\$(tar tzf "fixed-\$MAJOR.tar.gz" | head -1 | cut -d/ -f1)
  tar xzf "fixed-\$MAJOR.tar.gz" -C /opt
  NEWDIRS="\$NEWDIRS /opt/\$TOP"
  if [ "\$MAJOR" = "\$DECODER_MAJOR" ]; then ln -sfn "/opt/\$TOP" /opt/java4shell/jdk; fi
done < /tmp/j4s_jlist.txt
echo true > /opt/java4shell/jdk_ok
# Remove the vulnerable builds for the trains we just patched: any old
# amazon-corretto-* dir whose major matches a patched train and that is not one
# of the freshly installed fixed dirs. Trains we did NOT patch are left in place
# (so a partial patch deliberately leaves the host EXPOSED on those).
PATCHED_MAJORS=\$(awk '{print \$1}' /tmp/j4s_jlist.txt)
for d in \$OLD; do
  case " \$NEWDIRS " in *" \$d "*) continue;; esac
  dmaj=\$(basename "\$d" | sed -n 's/^amazon-corretto-\([0-9]*\)\..*/\1/p')
  for m in \$PATCHED_MAJORS; do
    if [ "\$dmaj" = "\$m" ]; then rm -rf "\$d"; break; fi
  done
done
# Recount installed JDKs so the wrapper's UNKNOWN gate stays honest.
ls -d /opt/amazon-corretto-* 2>/dev/null | wc -l > /opt/java4shell/jdk_count
systemctl restart java4shell-decoder
/opt/java4shell/exposure-check.sh
PATCH

  echo "NOTE: applying fix on ${role} (download + install + swap + prune + re-check)..."
  echo "      trains: ${TRAINS[*]:-all (17 21 25)}"
  out=$(run_onbox "${id}" "${patch_cmd}")
  new_verdict=$(echo "${out}" | sed -n 's/^VERDICT=//p')
  new_java=$(echo "${out}"    | sed -n 's/^JAVA_VERSION=//p')

  echo "---------------------------------------------------------------------------------"
  printf '  %-12s Java now: %-11s Verdict now: %s\n' "${role}" \
    "${new_java:-?}" "${new_verdict:-?}"
  echo "  Per-JDK after patch:"
  echo "${out}" | sed -n 's/^JVM|installed|[^|]*|\([^|]*\)|\([^|]*\)|.*/    \1  ->  \2/p'
  if [ "${new_verdict}" = "NOT_EXPOSED" ]; then
    echo "  SUCCESS: ${role} is no longer exposed to CVE-2026-114938."
    return 0
  fi
  if [ "${#TRAINS[@]}" -gt 0 ]; then
    echo "  NOTE: partial patch (${TRAINS[*]}) — ${role} is still '${new_verdict}' because"
    echo "        the untouched train(s) remain vulnerable. Re-run with no train filter to fully patch."
    return 0
  fi
  echo "  WARNING: expected NOT_EXPOSED, got '${new_verdict:-?}'. Full output:"
  echo "${out}"
  return 1
}

echo "================================================================================="
echo "  patch.sh — remediating: ${ROLES[*]}"
echo "================================================================================="
rc=0
for role in "${ROLES[@]}"; do
  patch_one "${role}" || rc=1
done
echo ""
echo "================================================================================="
[ "${rc}" -eq 0 ] && echo "  RESULT: all targeted nodes patched as requested." \
  || echo "  RESULT: one or more nodes did not reach NOT_EXPOSED — see above."
echo "================================================================================="
exit "${rc}"
