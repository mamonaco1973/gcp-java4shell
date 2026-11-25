#!/bin/bash
set -euo pipefail

# ================================================================================
# destroy.sh — tear the lab down
# The stack is a single phase with no external state, so one destroy is enough.
# ================================================================================

terraform -chdir=01-java4shell destroy -auto-approve
