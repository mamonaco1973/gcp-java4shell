# ================================================================================
# Outputs
# Resource names carry a per-deployment suffix, so the harness scripts cannot
# look anything up by a hardcoded name. These outputs are how check-exposure.sh,
# patch.sh, validate.sh, and lab-verdicts.sh find the right nodes for THIS
# deployment. Everything is keyed by role name.
# ================================================================================

output "deployment_name" {
  description = "Base name shared by every resource in this deployment"
  value       = local.name
}

output "region" {
  description = "Region the stack is deployed in"
  value       = var.region
}

# Map of role -> instance ID, e.g. {"vuln-x86" = "i-0abc...", ...}
output "node_ids" {
  description = "Instance ID for each lab node, keyed by role"
  value       = { for role, inst in aws_instance.node : role => inst.id }
}

# Map of role -> private IP (handy when opening an SSM port-forward)
output "node_private_ips" {
  description = "Private IP for each lab node, keyed by role"
  value       = { for role, inst in aws_instance.node : role => inst.private_ip }
}

# Map of role -> the verdict the lab is designed to produce. validate.sh asserts
# the live verdict against this; patch.sh patches the EXPOSED ones by default.
output "node_expected" {
  description = "Intended exposure verdict for each node, keyed by role"
  value       = { for role, node in local.nodes : role => node.expected }
}

# Which train the decoder runs on, and therefore the JDK symlink patch.sh
# repoints to the fixed build.
output "decoder_major" {
  description = "Major version the exposure-surface decoder service runs on"
  value       = local.decoder_major
}

# Map of role -> the AFFECTED JDK list that node installs (major/version/url).
# Print it to confirm every vulnerable build still resolves (HTTP 200) before
# trusting the verdicts. check_env.sh HEAD-checks these before apply.
output "affected_jdks" {
  description = "Affected JDK trains installed on each node (major, version, url)"
  value       = { for role, node in local.nodes : role => node.jdks }
}

# Map of role -> the FIXED JDK list patch.sh installs on that node, arch-matched.
# patch.sh upgrades every train and removes the vulnerable builds.
output "patch_jdks" {
  description = "Fixed Corretto builds patch.sh installs on each node (major, url)"
  value       = local.patch_jdks
}

output "ssm_portforward_hint" {
  description = "How to reach a node's verdict page over SSM (no port is exposed)"
  value       = "aws ssm start-session --region ${var.region} --target <node_id> --document-name AWS-StartPortForwardingSession --parameters '{\"portNumber\":[\"80\"],\"localPortNumber\":[\"8088\"]}' then open http://localhost:8088/"
}
