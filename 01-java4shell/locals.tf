# ================================================================================
# Deployment Identity
# Every named resource derives from local.name so the whole stack can be
# deployed more than once in the same project without colliding on
# project-global names (networks, firewall rules, instances). The suffix is generated once and
# held in state, so it is stable across repeated applies of the same deployment.
# ================================================================================

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

locals {
  # Base name every resource builds on, e.g. "java4shell-k3n8q2"
  name = "java4shell-${random_string.suffix.result}"

  corretto_base = "https://corretto.aws/downloads/resources"

  # ------------------------------------------------------------------------------
  # The three affected JDK trains and their fixes, read from variables.tf.
  #
  # Each lab node installs the AFFECTED build of ALL THREE trains (17 / 21 / 25);
  # patch.sh installs the FIXED build of all three. The detector keys off the
  # upstream version in each JDK's own release file, so these build strings are
  # what decide the per-train verdict — the lab does not hardcode a single JDK.
  # ------------------------------------------------------------------------------
  trains = {
    "17" = {
      affected_build   = var.corretto_jdk17_build
      affected_version = var.jdk17_version
      fixed_build      = var.corretto_jdk17_fixed_build
    }
    "21" = {
      affected_build   = var.corretto_affected_build
      affected_version = var.affected_version
      fixed_build      = var.corretto_fixed_build
    }
    "25" = {
      affected_build   = var.corretto_jdk25_build
      affected_version = var.jdk25_version
      fixed_build      = var.corretto_jdk25_fixed_build
    }
  }

  # Corretto's archive layout is stable and predictable, so we only ever edit the
  # build string. URLs are assembled inline per list (Terraform has no local
  # functions). The often-pulled vulnerable 21 x64 build honours an override.
  affected_jdks_x64 = [
    for major, t in local.trains : {
      major   = major
      version = t.affected_version
      url = (major == "21" && var.corretto_affected_url_override != "") ? var.corretto_affected_url_override : (
      "${local.corretto_base}/${t.affected_build}/amazon-corretto-${t.affected_build}-linux-x64.tar.gz")
    }
  ]
  affected_jdks_arm = [
    for major, t in local.trains : {
      major   = major
      version = t.affected_version
      url     = "${local.corretto_base}/${t.affected_build}/amazon-corretto-${t.affected_build}-linux-aarch64.tar.gz"
    }
  ]
  fixed_jdks_x64 = [
    for major, t in local.trains : {
      major = major
      url   = "${local.corretto_base}/${t.fixed_build}/amazon-corretto-${t.fixed_build}-linux-x64.tar.gz"
    }
  ]
  fixed_jdks_arm = [
    for major, t in local.trains : {
      major = major
      url   = "${local.corretto_base}/${t.fixed_build}/amazon-corretto-${t.fixed_build}-linux-aarch64.tar.gz"
    }
  ]

  # The train the exposure-surface decoder service runs on (the others are still
  # installed and still judged by the detector — they just aren't the live app).
  decoder_major = var.decoder_train

  # ------------------------------------------------------------------------------
  # Node definitions — the one place that describes every machine.
  # Three nodes, one per CPU class, each carrying ALL THREE vulnerable trains:
  #
  #   vuln-x86    n2-standard-2 (Ice Lake)  x86-64 WITH AVX-512 VBMI   -> EXPOSED
  #   safe-arm    c4a-standard-1 (Axion)    ARM64 (no VBMI)            -> NOT_EXPOSED
  #   safe-intel  n1-standard-1             x86-64 WITHOUT VBMI        -> NOT_EXPOSED
  #
  # The three nodes carry the same three vulnerable JDKs; only the CPU differs,
  # which is the whole point — exposure is CPU-bound, so the detector must find
  # all three JDKs AND gate on the instruction set. instances.tf iterates this
  # map; each node's startup script installs its arch-matched `jdks` list.
  #
  # min_cpu_platform is null where the family already decides the answer (N1 has
  # no VBMI-capable generation; C4A is ARM). C4A only boots from Hyperdisk.
  # ------------------------------------------------------------------------------
  nodes = {
    "vuln-x86" = {
      role      = "vuln-x86"
      image     = data.google_compute_image.ubuntu_x86.self_link
      machine   = var.x86_machine_type
      min_cpu   = var.x86_min_cpu_platform
      disk_type = "pd-balanced"
      arch      = "x64"
      jdks      = local.affected_jdks_x64
      expected  = "EXPOSED"
      reason    = "three vulnerable JDK trains (17/21/25) on an AVX-512 VBMI CPU"
    }
    "safe-arm" = {
      role      = "safe-arm"
      image     = data.google_compute_image.ubuntu_arm.self_link
      machine   = var.arm_machine_type
      min_cpu   = null
      disk_type = "hyperdisk-balanced"
      arch      = "aarch64"
      jdks      = local.affected_jdks_arm
      expected  = "NOT_EXPOSED"
      reason    = "same three vulnerable trains, but ARM64 has no AVX-512 VBMI intrinsic"
    }
    "safe-intel" = {
      role      = "safe-intel"
      image     = data.google_compute_image.ubuntu_x86.self_link
      machine   = var.intel_novbmi_machine_type
      min_cpu   = null
      disk_type = "pd-balanced"
      arch      = "x64"
      jdks      = local.affected_jdks_x64
      expected  = "NOT_EXPOSED"
      reason    = "x86, but this Intel chip has no AVX-512 VBMI instruction"
    }
  }

  # patch.sh target map: role -> the FIXED build of every train, arch-matched.
  # Patching a node upgrades all three trains and removes the vulnerable ones.
  patch_jdks = {
    for role, node in local.nodes :
    role => (node.arch == "aarch64" ? local.fixed_jdks_arm : local.fixed_jdks_x64)
  }
}
