# CLAUDE.md — gcp-java4shell

## What This Project Does

An **intentionally vulnerable** educational lab for **CVE-2026-114938**
("Java4Shell"), the AVX-512 `java.util.Base64` decode-intrinsic memory
corruption in OpenJDK. Three Compute Engine nodes demonstrate that
exploitability is CPU-bound: a vulnerable JDK is EXPOSED on an x86-64 AVX-512
VBMI CPU but immune on ARM64 and on x86 without VBMI. The repo covers the
defensive workflow — exposure detection, mitigation, and patch verification.

**No exploit code lives here by design.** The repo builds the infrastructure
and the (benign) exposure surface; the user runs the researchers' external PoC
(`calif.io/java4shell`) against their own isolated lab.

## Commands

```bash
./apply.sh                      # check env + APIs, terraform init + apply, then validate
./validate.sh                   # assert each node's live verdict == intended, with per-JDK rows
./lab-verdicts.sh [node...]     # print live verdict(s) + per-JDK breakdown over IAP SSH
./patch.sh [node] [train...]    # upgrade a node's JDKs in place to the fixed builds, re-check
                                #   (all 3 trains by default; name trains for a partial/mixed patch)
./destroy.sh                    # teardown
```

`iap-common.sh` is sourced by validate/lab-verdicts/patch: it reads the
Terraform outputs and provides `run_onbox` (pipe a script to the node over
`gcloud compute ssh --tunnel-through-iap`, run as root with stdin closed) and
`wait_ssh`.

## Architecture

Single Terraform phase in `01-java4shell/`. No modules, no workspaces, no load
balancer, no MIG.

- **Region/zone:** us-east1 / us-east1-b (`var.region`, `var.zone`). The zone
  must offer N2 Ice Lake, N1 and C4A. us-central1 avoided (capacity).
- **Auth:** `./credentials.json` (gitignored service-account key); project ID is
  read from it. `check_env.sh` activates it and runs `api_setup.sh`
  (compute, iap, cloudresourcemanager).
- **Nodes:** three, one per CPU class, and **every node installs all three
  affected trains (17.0.13 + 21.0.13 + 25.0.5)** arch-matched:
  `vuln-x86` (n2-standard-2 with `min_cpu_platform = "Intel Ice Lake"`, AVX-512
  VBMI → EXPOSED — the pin is essential, unpinned N2 may land on Cascade Lake),
  `safe-arm` (c4a-standard-1, Google Axion ARM → immune; Hyperdisk boot only),
  `safe-intel` (n1-standard-1, Haswell..Skylake, x86 without VBMI → immune).
  The detector judges every installed JDK (worst-wins). No pre-patched node;
  `patch.sh` upgrades all three trains live (or a named subset → mixed EXPOSED
  host). Defined once in `locals.tf` → `local.trains` and `local.nodes`;
  `var.decoder_train` picks the decoder's train (default 21).
- **OS:** Ubuntu 24.04 LTS — image families `ubuntu-2404-lts-amd64` /
  `ubuntu-2404-lts-arm64` (two data sources in `main.tf`).
- **Access:** IAP only — no external IPs; one firewall rule admits
  35.235.240.0/20 on tcp 22/80/8080 to the deployment's network tag. Egress via
  Cloud NAT. No OS Login; gcloud pushes SSH keys to metadata
  (`metadata["ssh-keys"]` drift is ignored).
- **Provisioning:** `scripts/userdata.sh.tftpl` is the GCE `startup-script`.
  The guest agent runs it on EVERY boot, so it exits early if
  `/root/userdata.done` exists (written last). validate.sh waits on that marker.
- **Exposure surface:** a minimal Java Base64-decode HTTP service
  (`Decoder.java`), run as `java4shell-decoder.service` on the decoder train.
- **Verdict:** `/opt/java4shell/exposure-check.sh` wraps the repo's portable
  `check-exposure.sh` (injected verbatim) and writes the page + `verdict.json`.
- **Boot log:** `/root/userdata.log` on each node.

## JDK Sourcing (important)

JDK builds are Amazon Corretto tarballs, pinned by **build string** in
`variables.tf` and assembled into URLs in `locals.tf`. Amazon may pull
vulnerable builds at any time; `check_env.sh` HEAD-checks every affected and
fixed URL before apply (warning only). `corretto_affected_url_override` lets
the 21 x64 build be self-hosted. The verdict logic keys off the **upstream**
version, so vendor/build changes are one-line edits. A failed download reads
`UNKNOWN`, never a false `NOT_EXPOSED`.

## Instance Access

```bash
terraform -chdir=01-java4shell output -json node_names
gcloud compute ssh <name> --zone us-east1-b --tunnel-through-iap
gcloud compute start-iap-tunnel <name> 80 --local-host-port=localhost:8088 --zone us-east1-b
```

## Verdict Logic

EXPOSED requires all three: vulnerable JDK, AVX-512 VBMI present, and no
mitigation flag on the running JVM. A patched JDK or a missing VBMI intrinsic is
NOT_EXPOSED outright; a vulnerable JDK+CPU with `-XX:-UseBASE64Intrinsics` or
`-XX:UseAVX=2` is MITIGATED.

## Multi-Deployment

Every resource name derives from `local.name` (`java4shell-<suffix>`), and the
firewall targets that name as a network tag. Scripts resolve resources through
`terraform output`, never a hardcoded name.

## Key Files

| File | Purpose |
|------|---------|
| `01-java4shell/main.tf` | provider (credentials.json) + two Ubuntu image lookups |
| `01-java4shell/variables.tf` | region/zone, machine types, JDK build strings, ports |
| `01-java4shell/locals.tf` | name suffix, derived Corretto URLs, `local.nodes` map |
| `01-java4shell/instances.tf` | the three nodes, startup script rendered from the template |
| `01-java4shell/networking.tf` | VPC, private subnet, Cloud Router + NAT |
| `01-java4shell/firewall.tf` | single IAP-only ingress rule |
| `01-java4shell/outputs.tf` | project/zone, node names/IPs, expected verdicts, JDK URLs, IAP hint |
| `01-java4shell/scripts/userdata.sh.tftpl` | installs Corretto, writes Decoder.java + exposure-check.sh, serves verdict |
