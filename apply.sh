#!/bin/bash
set -euo pipefail

# ================================================================================
# apply.sh — stand up the Java4Shell lab
# Checks the local toolchain, then init + apply the single Terraform phase, then
# validate. DEPLOY_START is set before terraform runs so validate.sh can report
# the full window (apply + boot + JDK install + first verdict).
# ================================================================================

./check_env.sh

terraform -chdir=01-java4shell init

export DEPLOY_START=$(date +%s)

terraform -chdir=01-java4shell apply -auto-approve

./validate.sh
