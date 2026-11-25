# ================================================================================
# Provider Configuration
# Pins the AWS provider to the 5.x major version. The ~> constraint allows
# minor-version upgrades (5.1, 5.2...) but blocks 6.x, preventing breaking
# changes from entering the build silently.
# ================================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }

    # Supplies the per-deployment name suffix defined in locals.tf
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# ================================================================================
# AMI Lookups — two architectures
# This lab deliberately mixes architectures: the two "exposed-surface" nodes
# run on x86-64 (where the AVX-512 VBMI Base64 intrinsic exists and CVE-2026-
# 114938 is reachable), and the control node runs on ARM64 (Graviton), where
# the vulnerable intrinsic does not exist at all. So we need both AMIs.
#
# Both are Canonical's Ubuntu 24.04 LTS, queried at plan time so no AMI ID is
# ever hard-coded. The only difference is the architecture token in the name.
# ================================================================================

# x86-64 image for the c7i (Intel Sapphire Rapids) nodes — vuln-jdk21, vuln-jdk17, vuln-jdk25 (and safe-intel on t3)
data "aws_ami" "ubuntu_x86" {
  most_recent = true
  owners      = ["099720109477"] # Canonical's official publisher account

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd*/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}

# ARM64 image for the t4g (Graviton) node — safe-arm
data "aws_ami" "ubuntu_arm" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd*/ubuntu-noble-24.04-arm64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}
