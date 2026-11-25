#!/bin/bash
set -euo pipefail

# ==============================================================================
# check-exposure.sh — is this host exposed to CVE-2026-114938 ("Java4Shell")?
# ==============================================================================
# A self-contained, READ-ONLY detector you can drop onto any Linux host. It
# attaches to nothing, writes nothing, and sends no network traffic. It decides
# exposure the way the published analyses do (JFrog, Datadog Security Labs):
# not with one hardcoded version, because exposure needs THREE things at once:
#
#   1. a vulnerable JDK build   (per-release fixed builds, below),
#   2. a CPU with the AVX-512 VBMI decode path   (the flaw lives in the
#      hand-written JVM intrinsic, which only runs on this instruction set), and
#   3. the intrinsic actually enabled   (no mitigating JVM flag).
#
# It inspects EVERY JVM on the box — running ones found through /proc, plus
# installed JDKs — because an OS package update never touches a runtime baked
# into an app or container image, so PATH's `java -version` is not the whole
# story.
#
# Method credit: JFrog Security Research and Datadog Security Labs. Verify the
# CVE and fixed-build numbers against Oracle/OpenJDK before you rely on them.
#
# Usage:
#   ./check-exposure.sh              # human report + exit code
#   ./check-exposure.sh --porcelain  # machine-readable KEY=value block
#   ./check-exposure.sh --no-exec    # never launch java (version from release
#                                    #   files only); for locked-down hosts
#   ./check-exposure.sh --root DIR   # also search DIR for JDKs (repeatable),
#                                    #   for site-specific install paths
#   ./check-exposure.sh --full       # search the whole filesystem (slow; also
#                                    #   finds JDKs inside container image layers)
# Exit: 0 = nothing exposed, 2 = a vulnerable unmitigated JVM, 1 = needs review.
# ==============================================================================

PORCELAIN=false
NO_EXEC=false
FULL=false
EXTRA_ROOTS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --porcelain) PORCELAIN=true ;;
    --no-exec)   NO_EXEC=true ;;
    --full)      FULL=true ;;
    --root)
      [ "$#" -ge 2 ] || { echo "--root needs a directory" >&2; exit 64; }
      EXTRA_ROOTS+=("$2"); shift ;;
    --root=*)    EXTRA_ROOTS+=("${1#--root=}") ;;
    -h|--help)   sed -n '4,35p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
  shift
done

# ------------------------------------------------------------------------------
# Fixed builds per release line — the upstream OpenJDK version at/after which
# the train is patched. These are the vendor-independent java.version strings
# (e.g. Corretto 21.0.13.1.2 reports "21.0.13.1"), so vendor does not matter.
# ------------------------------------------------------------------------------
declare -A FIXED=([17]="17.0.21.1" [21]="21.0.13.1" [25]="25.0.5.1"
                  [27]="27.0.1.1")
# 17 only became affected at 17.0.6; earlier 17s never had the intrinsic.
AFFECTED_FROM_17="17.0.6"
# End-of-life trains that carry the bug but will never get a fix: upgrade off.
EOL_VULN=" 18 19 20 22 23 24 26 "
# The CPU feature set the vulnerable decode intrinsic is compiled against. All
# four must be present; VBMI alone is not enough on every microarchitecture.
CPU_FLAGS=(avx512f avx512bw avx512vbmi bmi2)

# ==============================================================================
# Version helpers
# ==============================================================================

# vge A B — true when version A >= version B (dotted-numeric, via sort -V).
vge() {
  [ "$1" = "$2" ] && return 0
  [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}

# normalize — upstream dotted version from a raw java.version string.
# "1.8.0_511" -> "8.0.511"; "21.0.13.1+2" -> "21.0.13.1"; drops any +build.
normalize() {
  local v="${1%%+*}"            # strip +build metadata
  v="${v%%-*}"                  # strip -ea / -LTS / vendor suffixes
  if [[ "$v" == 1.* ]]; then    # legacy 1.x.0_u -> x.0.u
    v="${v#1.}"; v="${v/_/.}"
  fi
  printf '%s' "$v"
}

# version_class VERSION RAW — NOT_AFFECTED | VULNERABLE | PATCHED | REVIEW.
# RAW is the untouched string, needed to spot the Oracle 8 Performance Pack.
version_class() {
  local v="$1" raw="$2" major="${1%%.*}"
  # The one affected 8: Oracle's "Performance Pack" (8u511b33-perf -> 8u513).
  if [[ "$raw" == *perf* ]] && [ "$major" = "8" ]; then
    local u="${raw#*u}"; u="${u%%b*}"
    [[ "$u" =~ ^[0-9]+$ ]] && { [ "$u" -lt 513 ] && echo VULNERABLE ||
      echo PATCHED; return; }
    echo REVIEW; return
  fi
  [ "$major" -le 16 ] 2>/dev/null && { echo NOT_AFFECTED; return; }
  if [ -n "${FIXED[$major]:-}" ]; then
    if [ "$major" = "17" ] && ! vge "$v" "$AFFECTED_FROM_17"; then
      echo NOT_AFFECTED; return
    fi
    vge "$v" "${FIXED[$major]}" && echo PATCHED || echo VULNERABLE
    return
  fi
  [[ "$EOL_VULN" == *" $major "* ]] && { echo VULNERABLE; return; }
  echo REVIEW                   # a train newer than we know about
}

# ==============================================================================
# CPU gate — the vulnerable intrinsic only exists on x86-64 with these flags.
# Computed once; it is a property of the host, not of any single JVM.
# ==============================================================================
cpu_exposed() {
  [ "$(uname -m)" = "x86_64" ] || return 1
  local line
  line=" $(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null) "
  for f in "${CPU_FLAGS[@]}"; do
    [[ "$line" == *" $f "* ]] || return 1
  done
  return 0
}

if cpu_exposed; then CPU_OK=yes; else CPU_OK=no; fi
ARCH="$(uname -m)"

# ==============================================================================
# Mitigation detection — any of the documented flags disables the fast path:
#   -XX:-UseBASE64Intrinsics (needs UnlockDiagnosticVMOptions), -XX:UseAVX<=2,
#   -XX:DisableIntrinsic=_base64_decodeBlock, or interpreter-only -Xint.
# A blob is the JVM's command line plus its option env vars.
# ==============================================================================
mitigated() {
  local blob="$1"
  [[ "$blob" == *"-XX:-UseBASE64Intrinsics"* ]] && return 0
  [[ "$blob" == *"UseBASE64Intrinsics=false"* ]] && return 0
  [[ "$blob" =~ -XX:UseAVX=[012]([^0-9]|$) ]] && return 0
  [[ "$blob" == *"_base64_decodeBlock"* ]] && return 0
  [[ "$blob" == *"-Xint"* ]] && return 0
  return 1
}

# ==============================================================================
# Per-JVM verdict
# ==============================================================================
# verdict VERSION BLOB -> "VERDICT|reason". VERSION is already normalized.
verdict() {
  local v="$1" blob="$2" cls
  cls="$(version_class "$v" "$blob")"
  case "$cls" in
    NOT_AFFECTED) echo "NOT_EXPOSED|JDK line is not affected ($v)";;
    PATCHED)      echo "NOT_EXPOSED|patched ($v at/above the fixed build)";;
    REVIEW)       echo "REVIEW|JDK $v is newer than this checker knows";;
    VULNERABLE)
      if [ "$CPU_OK" = no ]; then
        echo "NOT_EXPOSED|CPU has no AVX-512 VBMI path ($ARCH) — intrinsic \
never runs"
      elif mitigated "$blob"; then
        echo "MITIGATED|vulnerable $v on a VBMI CPU, intrinsic disabled by flag"
      else
        echo "EXPOSED|vulnerable $v on an AVX-512 VBMI CPU, intrinsic active"
      fi;;
  esac
}

# ==============================================================================
# Discovery — every JVM on the host
# ==============================================================================
# jvm_version HOME_OR_BIN — upstream version from a release file, else by
# running the binary (unless --no-exec). Echoes "" when it cannot tell.
jvm_version() {
  local p="$1" home rel raw=""
  home="$p"; [ -x "$p" ] && home="$(dirname "$(dirname "$p")")"
  rel="$home/release"
  if [ -r "$rel" ]; then
    raw="$(sed -n 's/^JAVA_VERSION="\?\([^"]*\)"\?.*/\1/p' "$rel" | head -1)"
  fi
  if [ -z "$raw" ] && [ "$NO_EXEC" = false ]; then
    local bin="$p"; [ -d "$p" ] && bin="$p/bin/java"
    if [ -x "$bin" ]; then
      # Minimal, side-effect-free launch; a hung JVM cannot wedge the scan.
      raw="$(timeout -k 2 15 env -u JAVA_TOOL_OPTIONS -u _JAVA_OPTIONS \
        -u JDK_JAVA_OPTIONS "$bin" -version 2>&1 |
        sed -n 's/.*version "\([^"]*\)".*/\1/p' | head -1)" || raw=""
    fi
  fi
  printf '%s' "$raw"
}

ROWS=()                         # "scope|where|version|verdict|reason"
add_row() { ROWS+=("$1|$2|$3|$4|$5"); }

# Running JVMs: a mapped libjvm.so is the reliable signal (covers JDKs with no
# "java" in the process name). Needs root to see other users' processes.
scan_running() {
  local pid exe ver raw blob v d r
  for d in /proc/[0-9]*; do
    [ -r "$d/maps" ] || continue
    grep -q '/libjvm\.so' "$d/maps" 2>/dev/null || continue
    pid="${d#/proc/}"
    exe="$(readlink -f "$d/exe" 2>/dev/null || true)"
    [ -n "$exe" ] || continue
    raw="$(jvm_version "$exe")"
    [ -n "$raw" ] || { add_row running "pid $pid" "unknown" REVIEW \
      "running JVM, version undetermined"; continue; }
    v="$(normalize "$raw")"
    # The JVM's own command line + option env vars decide mitigation.
    blob="$(tr '\0' ' ' <"$d/cmdline" 2>/dev/null || true) "
    blob+="$(tr '\0' '\n' <"$d/environ" 2>/dev/null |
            grep -E '^(JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS)=' |
            tr '\n' ' ' || true)"
    IFS='|' read -r r rsn <<<"$(verdict "$v" "$blob")"
    add_row running "pid $pid" "$v" "$r" "$rsn"
  done
}

# Every java/javac binary we can discover, from many sources — PATH, JAVA_HOME,
# the alternatives system, the standard cross-distro install roots (including
# RHEL's lib64 and snap), the places apps bundle their own runtime (/usr/share,
# /usr/local, /srv, /app), user homes (unpacked tarballs, SDKMAN, IDE runtimes),
# any --root DIR, or the whole filesystem with --full. Overlap between sources is
# fine: scan_installed de-dupes by JDK home. Each producer is guarded so a miss
# (no javac, no alternatives, an unset JAVA_HOME, an absent root) cannot trip the
# script's `set -e` — notably `command -v java` exits non-zero when java is not
# on PATH, which is the normal case for a JDK that lives only under /opt.
jdk_candidates() {
  command -v java  2>/dev/null || true
  command -v javac 2>/dev/null || true
  if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
    printf '%s\n' "$JAVA_HOME/bin/java"
  fi
  if command -v update-alternatives >/dev/null 2>&1; then
    update-alternatives --list java  2>/dev/null || true
    update-alternatives --list javac 2>/dev/null || true
  fi
  local roots
  if [ "$FULL" = true ]; then
    # Every local disk mount (kernel pseudo-filesystems and network shares
    # excluded); -xdev keeps each walk on its own mount.
    mapfile -t roots < <(awk '$3 ~ /^(ext[234]|xfs|btrfs|zfs|overlay|vfat|f2fs)$/ \
      { print $2 }' /proc/mounts | sort -u)
    find "${roots[@]}" -xdev -name java -type f 2>/dev/null || true
    return 0
  fi
  # -maxdepth 8: vendors nest a JDK several levels deep (…/suite/runtime/jdk).
  # /usr/share holds runtimes bundled by packaged apps (Elasticsearch, IDEs).
  # -xdev and local_only keep the walk off network mounts, which can be huge
  # and slow (an NFS home, a cloud-drive FUSE mount under someone's home).
  mapfile -t roots < <(local_only /usr/lib/jvm /usr/lib64/jvm /usr/java /opt \
    /snap /usr/local /usr/share /srv /app /root /home)
  if [ "${#roots[@]}" -gt 0 ]; then
    find "${roots[@]}" -xdev -maxdepth 8 -name java -type f 2>/dev/null || true
  fi
  # --root DIR is searched as given, wherever it lives.
  if [ "${#EXTRA_ROOTS[@]}" -gt 0 ]; then
    find "${EXTRA_ROOTS[@]}" -maxdepth 12 -name java -type f 2>/dev/null || true
  fi
}

# local_only DIR... — echo each DIR that exists and is not on a network or
# FUSE filesystem.
local_only() {
  local d t
  for d in "$@"; do
    [ -d "$d" ] || continue
    t="$(stat -f -c %T "$d" 2>/dev/null || echo unknown)"
    case "$t" in
      nfs*|cifs|smb*|fuse*|9p|ceph|sshfs|glusterfs|unknown) continue ;;
    esac
    printf '%s\n' "$d"
  done
}

# is_jdk_home DIR — true when DIR holds a Java runtime: a release file or a
# libjvm.so (lib/server/ on 9+, jre/lib/<arch>/server/ on 8). Wider searches
# turn up other files named "java" (wrapper scripts, completion files); this
# keeps the scan from judging them, or launching them to read a version.
is_jdk_home() {
  [ -r "$1/release" ] && return 0
  [ -n "$(find "$1" -maxdepth 5 -name libjvm.so -print -quit 2>/dev/null)" ]
}

# Installed JDKs (may be idle): judge every one jdk_candidates found, de-duped by
# JDK home so a JDK's java and javac — and any PATH/alternatives symlink into it —
# collapse to a single entry. Idle JDKs cannot carry a runtime flag, so their
# verdict assumes the intrinsic is enabled (the safe default). A JDK whose version
# cannot be read (no release file, and --no-exec forbids launching it) is reported
# REVIEW, never dropped: silently skipping it could hide a vulnerable runtime
# behind a passing NOT_EXPOSED.
scan_installed() {
  local seen=" " bin real home raw v r rsn
  while IFS= read -r bin; do
    [ -x "$bin" ] || continue
    real="$(readlink -f "$bin" 2>/dev/null || true)"
    [ -n "$real" ] || continue
    home="$(dirname "$(dirname "$real")")"
    [[ "$seen" != *" $home "* ]] || continue
    seen+="$home "
    is_jdk_home "$home" || continue
    raw="$(jvm_version "$real")"
    if [ -z "$raw" ]; then
      add_row installed "$home" "unknown" REVIEW \
        "installed JDK, version undetermined (no release file; re-run without --no-exec)"
      continue
    fi
    v="$(normalize "$raw")"
    IFS='|' read -r r rsn <<<"$(verdict "$v" "")"
    add_row installed "$home" "$v" "$r" "$rsn"
  done < <(jdk_candidates | sort -u)
}

scan_running
scan_installed

# ==============================================================================
# Report — worst verdict wins for the host summary
# ==============================================================================
RANK() { case "$1" in EXPOSED) echo 3;; REVIEW) echo 2;; MITIGATED) echo 1;;
  *) echo 0;; esac; }
# Tie-break within the top verdict: prefer the most security-relevant reason, so
# "vulnerable build, but this CPU can't run the intrinsic" (or a mitigating flag)
# is not hidden behind a plain "patched" line from another JDK on the same host.
REASON_RANK() { case "$1" in
  *"no AVX-512 VBMI path"*|*"intrinsic disabled by flag"*) echo 2;; *) echo 1;;
esac; }
HOST_VERDICT=""; HOST_VER="none"; HOST_REASON="no JVM found"
for row in "${ROWS[@]:-}"; do
  [ -n "$row" ] || continue
  IFS='|' read -r _ _ v r rsn <<<"$row"
  if [ -z "$HOST_VERDICT" ]; then
    HOST_VERDICT="$r"; HOST_VER="$v"; HOST_REASON="$rsn"; continue
  fi
  rr="$(RANK "$r")"; cur="$(RANK "$HOST_VERDICT")"
  if [ "$rr" -gt "$cur" ] || { [ "$rr" -eq "$cur" ] && \
     [ "$(REASON_RANK "$rsn")" -gt "$(REASON_RANK "$HOST_REASON")" ]; }; then
    HOST_VERDICT="$r"; HOST_VER="$v"; HOST_REASON="$rsn"
  fi
done
[ -n "$HOST_VERDICT" ] || HOST_VERDICT="NOT_EXPOSED"

if [ "$PORCELAIN" = true ]; then
  # Keys consumed by the lab's validate.sh / patch.sh over SSM.
  echo "VERDICT=$HOST_VERDICT"
  echo "JAVA_VERSION=$HOST_VER"
  echo "ARCH=$ARCH"
  echo "AVX512_VBMI=$CPU_OK"
  echo "REASON=$HOST_REASON"
  for row in "${ROWS[@]:-}"; do
    [ -n "$row" ] && echo "JVM|$row"
  done
else
  printf 'CVE-2026-114938 (Java4Shell) exposure — %s\n' "$(hostname)"
  printf 'CPU AVX-512 VBMI path: %s   Arch: %s\n\n' "$CPU_OK" "$ARCH"
  if [ "${#ROWS[@]}" -eq 0 ]; then
    echo "No JVM found on this host."
  else
    printf '%-10s %-26s %-12s %-12s %s\n' SCOPE WHERE JAVA VERDICT REASON
    printf -- '-------------------------------------------------------------'
    printf -- '-------------------------\n'
    for row in "${ROWS[@]}"; do
      IFS='|' read -r scope where v r rsn <<<"$row"
      printf '%-10s %-26s %-12s %-12s %s\n' "$scope" "$where" "$v" "$r" "$rsn"
    done
  fi
  printf '\nHOST VERDICT: %s — %s\n' "$HOST_VERDICT" "$HOST_REASON"
  [ "$CPU_OK" = no ] && printf '%s\n' \
    "Note: this CPU has no AVX-512 VBMI path, so no JVM here is exploitable."
fi

case "$HOST_VERDICT" in
  EXPOSED) exit 2;;
  REVIEW)  exit 1;;
  *)       exit 0;;
esac
