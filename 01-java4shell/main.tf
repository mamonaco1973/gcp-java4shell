# ================================================================================
# Provider Configuration
# Authenticates via credentials.json — the service account key generated during
# GCP project setup. The project ID is read from the key file, so no variable is
# needed for it.
# ================================================================================

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }

    # Supplies the per-deployment name suffix defined in locals.tf
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

locals {
  credentials = jsondecode(file("../credentials.json"))
}

provider "google" {
  project     = local.credentials.project_id
  credentials = file("../credentials.json")
  region      = var.region
  zone        = var.zone
}

# ================================================================================
# Image Lookups — two architectures
# This lab deliberately mixes architectures: the x86-64 nodes (where the AVX-512
# VBMI Base64 intrinsic may exist and CVE-2026-114938 is reachable) and the ARM64
# control node (Google Axion), where the vulnerable intrinsic does not exist at
# all. So we need both images.
#
# Both are Canonical's Ubuntu 24.04 LTS, resolved from the image family at plan
# time so no image name is ever hard-coded.
# ================================================================================

# x86-64 image for vuln-x86 (N2 Ice Lake) and safe-intel (N1)
data "google_compute_image" "ubuntu_x86" {
  family  = "ubuntu-2404-lts-amd64"
  project = "ubuntu-os-cloud"
}

# ARM64 image for the C4A (Axion) node — safe-arm
data "google_compute_image" "ubuntu_arm" {
  family  = "ubuntu-2404-lts-arm64"
  project = "ubuntu-os-cloud"
}
