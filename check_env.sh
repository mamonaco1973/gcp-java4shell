#!/bin/bash
set -euo pipefail

# ================================================================================
# Environment Check
# Validates required tools are installed and credentials.json is present, then
# activates the service account and enables the APIs. This lab drives the nodes
# entirely over IAP SSH, so jq is required (the operator scripts parse Terraform
# JSON output with it).
# ================================================================================

echo "NOTE: Validating that required commands are found in your PATH."

for cmd in gcloud terraform jq; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: $cmd is not found in PATH."
    exit 1
  fi
  echo "NOTE: $cmd is found in the current PATH."
done

echo "NOTE: All required commands are available."

# ------------------------------------------------------------------------------
# Credentials
# The GCP provider and the operator scripts authenticate via this key file.
# ------------------------------------------------------------------------------

if [[ ! -f "./credentials.json" ]]; then
  echo "ERROR: ./credentials.json not found. Generate a service account key and place it here."
  exit 1
fi

echo "NOTE: credentials.json found."
gcloud auth activate-service-account --key-file="./credentials.json"
echo "NOTE: Service account activated successfully."

# ------------------------------------------------------------------------------
# API Setup
# Enable required GCP APIs before Terraform runs — idempotent, safe to re-run.
# ------------------------------------------------------------------------------

./api_setup.sh

# ------------------------------------------------------------------------------
# Corretto build preflight (WARNING only, never blocks apply)
# The nodes download pinned Corretto builds, and Amazon can pull a vulnerable
# build from the public archive at any time (that is how 17.0.21.0.3 vanished,
# leaving a node with no JDK). HEAD-check every affected AND patch build here so
# a pulled build is an obvious warning BEFORE apply — not a silent JAVA=none or
# a patch that never flips. Runs before `terraform init`, so the build strings
# are read from variables.tf defaults rather than Terraform state.
# ------------------------------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
  echo "NOTE: Checking that the pinned Corretto build URLs still resolve."
  VARS="01-java4shell/variables.tf"
  BASE="https://corretto.aws/downloads/resources"

  dflt() { grep -A4 "variable \"$1\"" "$VARS" | grep -m1 'default' \
             | sed 's/.*default *= *"\([^"]*\)".*/\1/'; }
  u() { echo "$BASE/$1/amazon-corretto-$1-linux-$2.tar.gz"; }
  http() { curl -s -o /dev/null -w '%{http_code}' -I --max-time 20 "$1" 2>/dev/null || echo 000; }

  AFF=$(dflt corretto_affected_build)
  FIX21=$(dflt corretto_fixed_build)
  AFF17=$(dflt corretto_jdk17_build)
  FIX17=$(dflt corretto_jdk17_fixed_build)
  AFF25=$(dflt corretto_jdk25_build)
  FIX25=$(dflt corretto_jdk25_fixed_build)
  OVERRIDE=$(dflt corretto_affected_url_override)
  AFF_X64_URL="$([ -n "$OVERRIDE" ] && echo "$OVERRIDE" || u "$AFF" x64)"

  warned=0
  check() {  # label  url
    local code
    code=$(http "$2")
    if [ "$code" = "200" ]; then
      echo "NOTE:    ok ($code)  $1"
    else
      echo "WARNING: $1 returned HTTP $code"
      echo "WARNING:   $2"
      echo "WARNING:   build may be pulled - fix the build string in variables.tf or set an override."
      warned=1
    fi
  }

  check "21 affected (x64)"     "$AFF_X64_URL"
  check "21 affected (aarch64)" "$(u "$AFF" aarch64)"
  check "17 affected (x64)"     "$(u "$AFF17" x64)"
  check "17 affected (aarch64)" "$(u "$AFF17" aarch64)"
  check "25 affected (x64)"     "$(u "$AFF25" x64)"
  check "25 affected (aarch64)" "$(u "$AFF25" aarch64)"
  check "patch 21 fixed (x64)"  "$(u "$FIX21" x64)"
  check "patch 17 fixed (x64)"  "$(u "$FIX17" x64)"
  check "patch 25 fixed (x64)"  "$(u "$FIX25" x64)"

  if [ "$warned" -eq 0 ]; then
    echo "NOTE: all pinned Corretto builds resolve."
  else
    echo "WARNING: one or more Corretto builds did not resolve (see above)."
    echo "WARNING: apply will continue - affected nodes read UNKNOWN; patch may not flip."
  fi
else
  echo "NOTE: curl not found - skipping the Corretto build-URL preflight."
fi
