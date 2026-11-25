# Java4Shell (CVE-2026-114938): a Cloud Exposure & Patch Lab

An **intentionally vulnerable** teaching lab for **CVE-2026-114938**
("Java4Shell") — the memory-corruption flaw in OpenJDK's AVX-512 `java.util.
Base64` decode intrinsic that Oracle/OpenJDK patched out-of-cycle on
**2026-11-17**. Built with Terraform in one phase.

The lab's point is **cloud-specific**: exploitability needs an x86-64 CPU with
**AVX-512 VBMI**, so the *same* vulnerable Java is harmless on **Graviton
(ARM64)**. Three nodes — one per CPU class — make that concrete, and **each
carries all three affected JDK trains (17 / 21 / 25) at once**, so the detector
has to judge every installed JDK, not just one. The tooling here handles the
defensive side — **exposure detection, mitigation, and patch
verification**.

> ### ⚠️ Intentionally vulnerable — do not deploy to production
> `vuln-x86` runs known-vulnerable JDKs on purpose. Every node sits in a
> private subnet with **no inbound path** and is reachable **only through SSM**.
> Do not run this in a shared or production account, and do not expose it to
> untrusted networks. Tear it down when you're done.

> **Scope of this repo:** infrastructure, the exposure surface, the detection
> tooling, and the patch. It contains **no exploit code and no attack payload**.
> The actual exploitation is done by the researchers' public PoC
> (`calif.io/java4shell`), which **you** clone and run against your own isolated
> lab — it is deliberately not reproduced or explained here.

## The three nodes

Every node installs **all three affected trains** — Corretto **17.0.13 +
21.0.13 + 25.0.5** (arch-matched) — so only the CPU differs between them:

| Node | Instance | CPU feature | JDKs installed | Verdict |
|---|---|---|---|---|
| **vuln-x86** | `c7i.large` (Intel Sapphire Rapids) | AVX-512 VBMI present | 17.0.13 + 21.0.13 + 25.0.5 (all affected) | **EXPOSED** |
| **safe-arm** | `t4g.micro` (Graviton2) | ARM64 — no VBMI | same three affected builds (aarch64) | **NOT EXPOSED** (CPU-immune) |
| **safe-intel** | `t3.micro` (Skylake/Cascade Lake) | x86 but **no VBMI** | same three affected builds | **NOT EXPOSED** (CPU-immune) |

Exposure requires **all three** of: a vulnerable JDK, an AVX-512 VBMI CPU, and
an app that decodes attacker-controlled Base64. All three nodes carry the same
three vulnerable JDKs; `safe-arm` and `safe-intel` fail only the **CPU**
condition — one is ARM, the other an older Intel chip without VBMI — which is
the point: *not all x86 is affected, only the chips that carry the instruction*.
On `vuln-x86` every train meets all three conditions, so the detector reports
**three EXPOSED JDKs** and the host verdict is EXPOSED; the detector lists each
train's own verdict, so a host with a mix of fine and vulnerable JDKs reads
correctly (worst-wins). There is **no pre-patched node**: the version fix is
shown live by `./patch.sh`, which upgrades **all three trains in place**
(`./patch.sh vuln-x86`) and flips the node EXPOSED → NOT_EXPOSED — or just one
train (`./patch.sh vuln-x86 17`) to demonstrate a still-exposed mixed host.

## Architecture

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="architecture-dark.svg">
  <img alt="The operator, running the AWS CLI and the public calif.io proof of concept, reaches the lab only through AWS SSM - Session Manager and Run Command - because the nodes have no inbound network path. SSM drives three nodes in private subnets, and every node installs all three affected Java trains at once (Corretto 17.0.13, 21.0.13 and 25.0.5), so the detector must judge every installed JDK. One node is EXPOSED: vuln-x86, a c7i x86 instance with the AVX-512 VBMI instruction the vulnerable intrinsic needs, so all three of its JDKs are exposed. The other two run the same three vulnerable JDKs but are immune because neither has AVX-512 VBMI: safe-arm, a t4g Graviton ARM64 instance, and safe-intel, a t3 x86 instance. There is no pre-patched node; patch.sh upgrades all three trains on a node live to flip it from EXPOSED to not exposed. The nodes egress through a NAT gateway to pull pinned JDK tarballs from the Amazon Corretto archive." src="architecture-light.svg">
</picture>

Regenerate with `python3 make_diagram.py`.

**`01-java4shell/`** is the whole stack: `networking.tf` (VPC, public/private
subnets, IGW, NAT), `security.tf` (one egress-only group — no ingress anywhere),
`iam.tf` (SSM role), `instances.tf` (the three nodes, rendered
from `locals.tf` + `scripts/userdata.sh.tftpl`), `variables.tf` (the JDK
coordinates), and `outputs.tf`.

## How a node decides its verdict

Each node's user data installs its pinned Corretto build, starts a **minimal
Base64-decode HTTP service** (the realistic exposure surface — a normal endpoint
that decodes caller-supplied input, like code parsing JWTs or basic-auth
headers), then runs the **portable detector**, `check-exposure.sh` — the exact
same script this repo ships and you can lift onto any host. It implements the
method published by [JFrog](https://research.jfrog.com/post/java4shell-vulnerability/)
and [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/java4shell-remote-code-execution-in-openjdk-cve-2026-114938/),
so a node is exposed only when **all three** hold:

1. **a vulnerable JDK** — compared against the per-release fixed builds
   (`17.0.21.1` / `21.0.13.1` / `25.0.5.1` / `27.0.1.1`), with EOL trains and the
   Oracle 8 Performance Pack handled — not a single hardcoded version;
2. **an AVX-512 VBMI CPU** — the full flag set the vulnerable intrinsic needs
   (`avx512f`, `avx512bw`, `avx512vbmi`, `bmi2`), so ARM/Graviton is immune;
3. **the intrinsic enabled** — no mitigating JVM flag.

The detector inspects **every** JVM on the box (running ones via `/proc`, plus
installed JDKs), not just `java` on PATH. Installed JDKs are found through PATH,
`JAVA_HOME`, `update-alternatives`, and a search of the usual install roots,
`/usr/share` and `/usr/local` (where apps bundle their own runtime), `/srv`,
`/app` and user homes. Network mounts are skipped. `--root DIR` adds a
site-specific path, and `--full` searches every local disk. A thin lab wrapper then serves the
verdict page on `:80` (reachable via an SSM tunnel).

## Commands

| Script | What it does |
|---|---|
| `./apply.sh` | check env, `terraform init && apply`, then `validate.sh` |
| `./validate.sh` | wait for all nodes on SSM, print each live verdict + per-JDK breakdown |
| `./check-exposure.sh` | **the portable detector** — read-only, run it on any host (`--porcelain`, `--no-exec`, `--root DIR`, `--full`); the same script the nodes run |
| `./lab-verdicts.sh [node...]` | print the live verdict + per-JDK breakdown for one/all lab nodes over SSM |
| `./patch.sh [node] [train...]` | upgrade a node's JDKs in place to the fixed builds, restart, re-check (EXPOSED → NOT_EXPOSED); all three trains by default, or only the named ones |
| `./destroy.sh` | tear everything down |

## Prerequisites

* [An AWS Account](https://aws.amazon.com/console/)
* [Install AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
* [Install Terraform](https://developer.hashicorp.com/terraform/install)
* [Install jq](https://jqlang.github.io/jq/download/)

No SSH client is needed — access is entirely through SSM Session Manager.

## ⚠️ Verify the vulnerable build before you deploy

Each node downloads the affected build of all three trains. The default
vulnerable 21 build is Corretto `21.0.13.0.11` — the last pre-patch 21 tag
before the fix `21.0.13.1.2`. But Amazon may pull vulnerable builds from the
public archive at any time, so confirm they still resolve and match what your
PoC targets. `check_env.sh` (run by `apply.sh`) HEAD-checks every affected and
fixed build before apply; you can also print the URLs in effect:

```bash
./check_env.sh                                                        # preflight all builds
terraform -chdir=01-java4shell output -json affected_jdks | jq -r '.["vuln-x86"][].url'
```

If any doesn't return `200`, set the matching build string in `variables.tf` to
the exact build your PoC targets, or stage the artifact yourself and point
`corretto_affected_url_override` at the 21 x64 build (see `variables.tf`). If a
download fails at boot, the node still comes up and reads **UNKNOWN** — never a
misleading "not exposed".

## Deploy

```bash
git clone https://github.com/mamonaco1973/aws-java4shell.git
cd aws-java4shell
./apply.sh
```

`validate.sh` then prints each node's live verdict, with the per-JDK breakdown
underneath so you can see the detector judged all three trains:

```
NODE         VERDICT      VBMI   JDKS
---------------------------------------------------------------------------------------
safe-arm     NOT_EXPOSED  no     3
                 17.0.13  ->  NOT_EXPOSED
                 21.0.13  ->  NOT_EXPOSED
                 25.0.5  ->  NOT_EXPOSED
safe-intel   NOT_EXPOSED  no     3
                 17.0.13  ->  NOT_EXPOSED
                 21.0.13  ->  NOT_EXPOSED
                 25.0.5  ->  NOT_EXPOSED
vuln-x86     EXPOSED      yes    3
                 17.0.13  ->  EXPOSED
                 21.0.13  ->  EXPOSED
                 25.0.5  ->  EXPOSED
```

## Try it

1. **See a verdict page.** Open an SSM tunnel to a node's web server and browse it
   (the page lists every installed JDK and its verdict):
   ```bash
   ID=$(terraform -chdir=01-java4shell output -json node_ids | jq -r '."vuln-x86"')
   aws ssm start-session --target "$ID" \
     --document-name AWS-StartPortForwardingSession \
     --parameters '{"portNumber":["80"],"localPortNumber":["8088"]}'
   # then open http://localhost:8088/
   ```
2. **Reach the decoder** (the exposure surface) the same way, forwarding
   `8080`, and point your `calif.io/java4shell` PoC at `localhost`.
3. **Remediate one train** to see a mixed host: `./patch.sh vuln-x86 17` leaves
   21 and 25 vulnerable, so the node stays `EXPOSED` with 17 now clean.
4. **Remediate fully:** `./patch.sh vuln-x86`, then `./lab-verdicts.sh vuln-x86`
   — all three trains upgrade and the verdict flips to `NOT_EXPOSED`.

## Teardown

```bash
./destroy.sh
```

## The vulnerability, briefly

| | |
|---|---|
| **CVE** | CVE-2026-114938 ("Java4Shell") |
| **Flaw** | memory corruption in HotSpot's AVX-512 `java.util.Base64` decode intrinsic, reachable pre-auth when a service decodes attacker-controlled Base64 |
| **Severity** | CVSS 4.0 **9.2** (Calif) / CVSS 3.1 **8.1** (Oracle/OpenJDK) |
| **Affected** | OpenJDK 17 (`17.0.6`→`17.0.13`), 21 (→`21.0.13`), 25 (→`25.0.5`), 27 (→`27.0.1`) on x86-64 **with AVX-512 VBMI**; ARM64 not affected |
| **Fixed** | `17.0.21.1`, `21.0.13.1`, `25.0.5.1`, `27.0.1.1` (Corretto: `…​.1.2` builds) — Oracle CPU of 2026-11-17 |
| **Temporary mitigation** | `-XX:+UnlockDiagnosticVMOptions -XX:-UseBASE64Intrinsics` **or** `-XX:UseAVX=2` (x86-only; keeps AVX2, drops AVX-512). Stopgaps only — upgrade is the fix. |

Sources: [DigiCert advisory](https://www.digicert.com/security-advisories/java4shell-vulnerabilities-what-you-need-to-know),
[OpenJDK advisory (2026-11-17)](https://openjdk.org/groups/vulnerability/advisories/2026-11-17),
[Oracle CPU](https://www.oracle.com/security-alerts/cspunov2026.html), Red Hat RHSB-2026-018.

## Notes

- **Lab only.** Intentionally vulnerable; private subnets; SSM-only; HTTP served
  to localhost over an SSM tunnel. Not for production.
- **JDK source.** Amazon Corretto, pinned by build string in `variables.tf`.
- **Exploit code.** Not in this repo by design — bring your own isolated PoC.
