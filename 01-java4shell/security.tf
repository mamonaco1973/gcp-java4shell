# ================================================================================
# Security Group
# A single egress-only group for all three nodes. There is NO ingress rule:
# nothing on the internet, and nothing inside the VPC, can open a connection to
# these instances. Operator access is exclusively through SSM Session Manager,
# which the SSM agent establishes as an OUTBOUND connection to the SSM service
# — so it needs no inbound rule here.
#
# The sample Base64 decode service and the verdict page are reached the same
# way: `aws ssm start-session` with AWS-StartPortForwardingSession tunnels a
# local port to the node over the agent channel. No port is ever exposed.
#
# This closed posture is deliberate for an intentionally-vulnerable lab: the
# only thing that should ever drive the vulnerable decoder is your own PoC,
# run through an SSM tunnel you open.
# ================================================================================

resource "aws_security_group" "node" {
  name        = "${local.name}-node-sg"
  description = "Egress-only; lab nodes are reachable only via SSM"
  vpc_id      = aws_vpc.main.id

  # Outbound allows Corretto downloads, apt, and the SSM endpoints through the
  # NAT gateway. No specific destination needs whitelisting.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name}-node-sg" }
}
