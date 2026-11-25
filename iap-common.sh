#!/bin/bash
# ================================================================================
# iap-common.sh — shared helpers sourced by validate.sh, lab-verdicts.sh and
# patch.sh. Reads this deployment's Terraform outputs and runs commands on a
# node over IAP-tunnelled SSH (the nodes have no external IP; the firewall
# admits only Google's IAP range).
# ================================================================================

CHDIR="01-java4shell"

PROJECT=$(terraform -chdir="$CHDIR" output -raw project_id 2>/dev/null || true)
if [ -z "${PROJECT}" ]; then
  echo "ERROR: could not read Terraform outputs. Run ./apply.sh first."
  exit 1
fi
ZONE=$(terraform -chdir="$CHDIR" output -raw zone)
REGION=$(terraform -chdir="$CHDIR" output -raw region)
NODE_NAMES_JSON=$(terraform -chdir="$CHDIR" output -json node_names)

# The service account in credentials.json is the identity the IAP tunnel uses.
if [ -f ./credentials.json ]; then
  gcloud auth activate-service-account --key-file=./credentials.json >/dev/null 2>&1 || true
fi

# Remote side: read the whole script from stdin FIRST, then run it as root with
# stdin closed — so nothing inside the script (curl, systemctl, the detector)
# can swallow the rest of it.
REMOTE_WRAPPER='sudo bash -c '\''S=$(cat); exec bash -c "$S" </dev/null'\'''

# run_onbox <instance-name> <shell script text>
# Echoes the remote stdout; returns the ssh exit status.
run_onbox() {
  local name="$1" cmd="$2"
  printf '%s\n' "${cmd}" | gcloud compute ssh "${name}" \
    --project "${PROJECT}" --zone "${ZONE}" \
    --tunnel-through-iap --quiet --strict-host-key-checking=no \
    --command "${REMOTE_WRAPPER}" -- -o LogLevel=ERROR 2>/dev/null
}

# wait_ssh <instance-name> <timeout-seconds>
# Block until the node accepts an IAP SSH session (guest agent up, key pushed).
wait_ssh() {
  local name="$1" timeout="$2" elapsed=0 poll=10
  while true; do
    [ "$(run_onbox "${name}" 'echo ok')" = "ok" ] && return 0
    elapsed=$((elapsed + poll))
    [ "${elapsed}" -ge "${timeout}" ] && return 1
    [ -n "${QUIET_WAIT:-}" ] || echo "NOTE: ${name} not reachable over IAP SSH yet — retrying in ${poll}s (${elapsed}s)..."
    sleep "${poll}"
  done
}

# node_name <role> — instance name for a role, empty if unknown
node_name() {
  echo "${NODE_NAMES_JSON}" | jq -r --arg r "$1" '.[$r] // empty'
}
