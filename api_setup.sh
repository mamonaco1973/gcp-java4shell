#!/bin/bash
# ================================================================================
# api_setup.sh
# Enables the GCP APIs gcp-java4shell needs before Terraform runs. Safe to
# re-run — enabling an already-enabled API is a no-op.
# ================================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Project Configuration
# Extract project ID from credentials.json rather than hard-coding it, so the
# script works across environments without modification.
# ------------------------------------------------------------------------------

project_id=$(jq -r '.project_id' "./credentials.json")

gcloud config set project "$project_id"

# ------------------------------------------------------------------------------
# API Enablement
# compute covers VMs, firewall, Cloud Router and Cloud NAT. iap carries the
# TCP-forwarding tunnel that is the only way onto the nodes.
# cloudresourcemanager is required by the Terraform Google provider.
# ------------------------------------------------------------------------------

echo "NOTE: Enabling required GCP APIs for project $project_id."

gcloud services enable compute.googleapis.com
gcloud services enable iap.googleapis.com
gcloud services enable cloudresourcemanager.googleapis.com

echo "NOTE: All required APIs are enabled."
