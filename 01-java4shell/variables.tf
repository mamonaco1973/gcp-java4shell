# ================================================================================
# Variables
# Everything that might need tuning between deployments lives here. The JDK
# coordinates are the important ones: they decide which Java build each node
# installs, and therefore whether that node is genuinely vulnerable to
# CVE-2026-114938 or not.
# ================================================================================

variable "region" {
  description = "AWS region for the whole stack"
  type        = string
  default     = "us-east-2"
}

# --------------------------------------------------------------------------------
# Instance types — the lab turns on the CPU distinction, so these are chosen
# deliberately:
#   x86_instance_type        c7i (Sapphire Rapids) — HAS AVX-512 VBMI, so the
#                            vulnerable intrinsic can run. The floor for VBMI is
#                            a .large; c6i.large (Ice Lake) is a cheaper swap.
#   intel_novbmi_instance_type  t3 (Skylake/Cascade Lake) — x86 but NO VBMI, so
#                            it is immune by HARDWARE despite being Intel. This
#                            is the whole point of the safe-intel node: not all
#                            x86 is affected, only the chips with the instruction.
#   arm_instance_type        t4g (Graviton2, ARM64) — no AVX-512 at all, immune.
# --------------------------------------------------------------------------------

variable "x86_instance_type" {
  description = "x86-64 nodes that MUST support AVX-512 VBMI (c7i / c6i / m6i / c7a)"
  type        = string
  default     = "c7i.large"
}

variable "intel_novbmi_instance_type" {
  description = "Intel x86 node WITHOUT AVX-512 VBMI (t3), to prove not all x86 is affected"
  type        = string
  default     = "t3.micro"
}

variable "arm_instance_type" {
  description = "Instance type for the Graviton/ARM64 control node"
  type        = string
  default     = "t4g.micro"
}

# --------------------------------------------------------------------------------
# JDK builds — Amazon Corretto
# Corretto keeps every published build at a stable, predictable URL:
#   https://corretto.aws/downloads/resources/<build>/amazon-corretto-<build>-linux-<arch>.tar.gz
# where <arch> is x64 or aarch64. locals.tf assembles the full URLs from the
# build strings below so you only edit the version in one place.
#
# Upstream (OpenJDK) version vs Corretto build string:
#   OpenJDK 21.0.13    (vulnerable)  <-- the last pre-emergency 21 build
#   OpenJDK 21.0.13.1  (fixed)       <-- Oracle's 2026-11-17 out-of-cycle patch
# Corretto expresses these as 5-part build strings (openjdk version + Corretto
# build number). `java -version` on the installed JDK still reports the upstream
# dotted version, which is what the verdict logic keys off — see exposure-check.
# --------------------------------------------------------------------------------

# FIXED build. DigiCert's advisory lists Corretto's patched 21 build as
# 21.0.13.1.2, and Amazon ships it as current, so this URL resolves today.
variable "corretto_fixed_build" {
  description = "Corretto build string for the PATCHED JDK (reports upstream 21.0.13.1)"
  type        = string
  default     = "21.0.13.1.2"
}

# AFFECTED build — the last pre-patch Corretto 21 build, which reports upstream
# 21.0.13. 21.0.13.0.11 is the real tag immediately before the emergency fix
# 21.0.13.1.2 (confirmed against github.com/corretto/corretto-21/tags), and both
# its x64 and aarch64 tarballs currently resolve (HTTP 200) on corretto.aws.
#
# >>> STILL VERIFY THIS IS WHAT YOUR PoC TARGETS. <<< Amazon may pull vulnerable
# builds from the public archive at any time. Before `./apply.sh`, confirm the
# assembled URL returns HTTP 200 — `output affected_jdk_url` prints it — and that
# calif.io's PoC was validated against this exact build. If it has been pulled,
# stage the tarball yourself and set corretto_affected_url_override.
#
# If the download fails at boot the node still comes up and stays reachable over
# SSM — its verdict reads "UNKNOWN / JDK INSTALL FAILED", never a false verdict.
variable "corretto_affected_build" {
  description = "Corretto build string for the VULNERABLE JDK (reports upstream 21.0.13)"
  type        = string
  default     = "21.0.13.0.11"
}

# Optional hard override for the affected tarball URL (both x64 and aarch64 are
# derived from the same build string by default). Set this to a self-hosted
# artifact if the public Corretto archive no longer carries the vulnerable build.
variable "corretto_affected_url_override" {
  description = "If non-empty, used verbatim as the affected x64 JDK URL instead of the derived Corretto URL"
  type        = string
  default     = ""
}

# A SECOND affected train, to prove the detector is not hardcoded to Java 21 and
# that patch.sh upgrades each train to ITS OWN fix. The fix is 17.0.21.1
# (Corretto 17.0.21.1.2, verified HTTP 200). For the affected build we use
# 17.0.13.11.1 (upstream 17.0.13) — a real Corretto 17 build that still resolves
# and sits below the 17.0.21.1 threshold, so it reads EXPOSED. (The advisory's
# "17.0.21.0.3" tag returns 403 on the Corretto archive; always verify.)
variable "corretto_jdk17_build" {
  description = "Corretto 17 build for the AFFECTED Java 17 node (reports 17.0.13, below the fix)"
  type        = string
  default     = "17.0.13.11.1"
}

variable "jdk17_version" {
  description = "Upstream version the affected Corretto 17 build reports"
  type        = string
  default     = "17.0.13"
}

variable "corretto_jdk17_fixed_build" {
  description = "Corretto 17 build patch.sh upgrades vuln-jdk17 to (reports upstream 17.0.21.1)"
  type        = string
  default     = "17.0.21.1.2"
}

# A THIRD affected train: Java 25 (current LTS). Affected through 25.0.5.0.10
# (upstream 25.0.5); fixed in Corretto 25.0.5.1.2 (upstream 25.0.5.1) per
# Corretto's own changelog. Java 27 is deliberately omitted: it is not released
# until Sep 2027, so there is no build to install (the detector still covers it).
variable "corretto_jdk25_build" {
  description = "Corretto 25 build for the AFFECTED Java 25 node (reports 25.0.5, below the fix)"
  type        = string
  default     = "25.0.5.0.10"
}

variable "jdk25_version" {
  description = "Upstream version the affected Corretto 25 build reports"
  type        = string
  default     = "25.0.5"
}

variable "corretto_jdk25_fixed_build" {
  description = "Corretto 25 build patch.sh upgrades vuln-jdk25 to (reports upstream 25.0.5.1)"
  type        = string
  default     = "25.0.5.1.2"
}

# --------------------------------------------------------------------------------
# Upstream version strings used by the verdict logic. Kept as variables so the
# detection threshold stays in lockstep with the builds installed above.
# --------------------------------------------------------------------------------

variable "affected_version" {
  description = "Upstream OpenJDK version the affected build reports"
  type        = string
  default     = "21.0.13"
}

variable "fixed_version" {
  description = "Upstream OpenJDK version at/after which the 21 train is patched"
  type        = string
  default     = "21.0.13.1"
}

# Port the benign Base64-decode service listens on (localhost / in-VPC only).
variable "decoder_port" {
  description = "TCP port for the sample Base64 decode service (the exposure surface)"
  type        = number
  default     = 8080
}

# Which train the exposure-surface decoder service runs on. All three trains are
# installed on every node and all three are judged by the detector; this only
# picks which JDK the (single) sample service executes under.
variable "decoder_train" {
  description = "Major version whose JDK the decoder service runs on (17, 21, or 25)"
  type        = string
  default     = "21"
}
