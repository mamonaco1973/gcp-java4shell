# CLAUDE.md — aws-java4shell

## What This Project Does

An **intentionally vulnerable** educational lab for **CVE-2026-114938**
("Java4Shell"), the AVX-512 `java.util.Base64` decode-intrinsic memory
corruption in OpenJDK. Three EC2 nodes demonstrate that exploitability is
CPU-bound: a vulnerable JDK is EXPOSED on an x86-64 AVX-512 VBMI CPU but immune
on ARM64. The repo covers the defensive workflow — exposure detection,
mitigation, and patch verification.

**No exploit code lives here by design.** The repo builds the infrastructure
and the (benign) exposure surface; the user runs the researchers' external PoC
(`calif.io/java4shell`) against their own isolated lab.

## Commands

```bash
./apply.sh                      # check env, terraform init + apply, then validate
./validate.sh                   # assert each node's live verdict == intended, with per-JDK rows
./lab-verdicts.sh [node...]     # print live verdict(s) + per-JDK breakdown over SSM
./patch.sh [node] [train...]    # upgrade a node's JDKs in place to the fixed builds, re-check
                                #   (all 3 trains by default; name trains for a partial/mixed patch)
./destroy.sh                    # teardown
```

## Architecture

Single Terraform phase in `01-java4shell/`. No modules, no workspaces, no ALB,
no ASG, no CloudWatch (dropped from the aws-autoscaling seed).

- **Region:** us-east-2 (var.region)
- **Nodes:** three, one per CPU class, and **every node installs all three
  affected trains (17.0.13 + 21.0.13 + 25.0.5)** arch-matched:
  `vuln-x86` (c7i.large, AVX-512 VBMI → EXPOSED, all three JDKs exposed),
  `safe-arm` (t4g.micro, ARM → immune), `safe-intel` (t3.micro, x86 without
  VBMI → immune). The detector judges every installed JDK (worst-wins), so a
  node's verdict rolls up its per-train verdicts. No pre-patched node;
  `patch.sh` upgrades all three trains on a node live (or a named subset, which
  leaves a mixed EXPOSED host). Defined once in `locals.tf` → `local.trains`
  (the 3 trains) and `local.nodes` (the 3 machines); `var.decoder_train` picks
  which train the decoder runs on (default 21).
- **OS:** Ubuntu 24.04 LTS — amd64 for the c7i/t3 nodes, arm64 for the t4g node
  (two AMI data sources in `main.tf`).
- **Access:** SSM only — private subnets, no public IP, no SSH, egress-only SG.
- **Exposure surface:** a minimal Java Base64-decode HTTP service
  (`scripts/userdata.sh.tftpl` writes `Decoder.java`), run as
  `java4shell-decoder.service` on the decoder train's JDK.
- **Verdict:** `/opt/java4shell/exposure-check.sh` (written by user data) is the
  single source of truth; it writes the verdict page + `verdict.json`.
- **Boot log:** `/root/userdata.log` on each node.

## JDK Sourcing (important)

JDK builds are Amazon Corretto tarballs, pinned by **build string** in
`variables.tf` and assembled into URLs in `locals.tf`:

- `corretto_fixed_build` (default `21.0.13.1.2`) — current, downloads fine.
- `corretto_affected_build` (default `21.0.13.11.1`) — the **vulnerable** build;
  **a best guess that must be verified**, since Amazon is pulling vulnerable
  builds post-patch. Confirm `output affected_jdk_url` returns HTTP 200, or set
  `corretto_affected_url_override` to a self-hosted artifact.

The verdict logic keys off the **upstream** version (`21.0.13` vs `21.0.13.1`),
which is vendor-independent, so changing vendor/build is a one-line edit.

If the affected download fails at boot, the node still comes up over SSM and its
verdict reads `UNKNOWN` ("JDK INSTALL FAILED"), never a false `NOT_EXPOSED`.

## Instance Access

Private, no SSH key. Session Manager:

```bash
aws ssm start-session --target <instance-id> --region us-east-2
```

Resolve IDs for this deployment (names carry a per-deploy suffix):

```bash
terraform -chdir=01-java4shell output -json node_ids
```

View a verdict page via a port-forward to the node's `:80`:

```bash
aws ssm start-session --target <id> \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["80"],"localPortNumber":["8088"]}'
```

## Verdict Logic

EXPOSED requires all three: vulnerable JDK (`version < fixed_version`),
AVX-512 VBMI present, and no mitigation flag on the running JVM. A patched JDK
or a missing VBMI intrinsic is NOT_EXPOSED outright; a vulnerable JDK+CPU with
`-XX:-UseBASE64Intrinsics` or `-XX:UseAVX=2` is MITIGATED.

## Multi-Deployment

Every resource name derives from `local.name` (`java4shell-<suffix>`) so the
stack can deploy more than once per account/region. Scripts resolve resources
through `terraform output`, never a hardcoded name. Each concurrent deployment
needs its own state (separate clone or `terraform workspace`).

## Key Files

| File | Purpose |
|------|---------|
| `01-java4shell/main.tf` | providers + two Ubuntu AMI lookups (amd64, arm64) |
| `01-java4shell/variables.tf` | JDK build strings/URLs, instance types, ports |
| `01-java4shell/locals.tf` | name suffix, derived Corretto URLs, `local.nodes` map |
| `01-java4shell/instances.tf` | the three nodes, rendered from the shared userdata template |
| `01-java4shell/networking.tf` | VPC, public/private subnets, IGW, NAT |
| `01-java4shell/security.tf` | single egress-only security group |
| `01-java4shell/iam.tf` | SSM role + instance profile |
| `01-java4shell/outputs.tf` | node IDs/IPs, expected verdicts, JDK URLs, SSM hints |
| `01-java4shell/scripts/userdata.sh.tftpl` | installs Corretto, writes Decoder.java + exposure-check.sh, serves verdict |
