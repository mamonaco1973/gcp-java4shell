# ================================================================================
# Lab Nodes
# Three standalone instances — no Auto Scaling group, because this lab is about
# comparing three fixed, individually-identifiable machines, not elasticity.
# Every node installs ALL THREE affected trains (17 / 21 / 25); only the CPU
# differs, which is the whole lesson:
#
#   vuln-x86     c7i.large   x86-64 AVX-512 VBMI      -> EXPOSED
#   safe-arm     t4g.micro   ARM64 (no VBMI)          -> NOT EXPOSED (CPU-immune)
#   safe-intel   t3.micro    x86-64 without VBMI      -> NOT EXPOSED (CPU-immune)
#
# All three are described once in local.nodes (locals.tf); this file just
# iterates that map so adding or retyping a node is a one-line change there.
#
# Each node's userdata is the shared template rendered with that node's values.
# "One userdata per node" is achieved through templatefile() rather than three
# near-identical copies — the nodes differ only in architecture, their JDK list,
# and the expected verdict, so a single reviewed template avoids drift.
# ================================================================================

resource "aws_instance" "node" {
  for_each = local.nodes

  ami                    = each.value.ami
  instance_type          = each.value.instance
  subnet_id              = each.value.subnet
  vpc_security_group_ids = [aws_security_group.node.id]
  iam_instance_profile   = aws_iam_instance_profile.ssm.name

  # Do not launch until egress exists. aws_nat_gateway blocks until the gateway
  # is "available" (~1-2 min) and the private route table association points the
  # subnet at it, so user data's JDK download has a working route from the first
  # second — instead of racing a NAT that is still coming up.
  depends_on = [
    aws_nat_gateway.main,
    aws_route_table_association.private_a,
    aws_route_table_association.private_b,
  ]

  # Private subnet — never a public IP. SSM is the only way in.
  associate_public_ip_address = false

  # Enforce IMDSv2 (token-required). The userdata uses the token flow, and this
  # is the AWS-recommended hardening default.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  root_block_device {
    volume_size = 16
    volume_type = "gp3"
    encrypted   = true
  }

  # gzip the rendered user data: injecting the full check-exposure.sh detector
  # (below) pushes it past EC2's 16 KB plaintext limit; cloud-init transparently
  # decompresses a gzip-magic payload.
  user_data_base64 = base64gzip(templatefile(
    "${path.module}/scripts/userdata.sh.tftpl", {
      node_role        = each.value.role
      expected_verdict = each.value.expected
      expected_reason  = each.value.reason
      arch             = each.value.arch
      decoder_major    = local.decoder_major
      decoder_port     = var.decoder_port
      deployment_name  = local.name
      # All three affected trains this node installs, one per line as
      # "major|version|url"; userdata loops over it and installs each.
      jdks = join("\n", [for j in each.value.jdks : "${j.major}|${j.version}|${j.url}"])
      # The portable detector, injected verbatim so the node runs the exact
      # same script we ship in the repo and viewers run on their own hosts.
      detector = file("${path.module}/../check-exposure.sh")
  }))

  tags = {
    Name            = "${local.name}-${each.value.role}"
    Role            = each.value.role
    Lab             = "java4shell"
    CVE             = "CVE-2026-114938"
    ExpectedVerdict = each.value.expected
  }
}
