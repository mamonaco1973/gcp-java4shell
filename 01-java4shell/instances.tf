# ================================================================================
# Lab Nodes
# Three standalone instances — no managed instance group, because this lab is
# about comparing three fixed, individually-identifiable machines, not elasticity.
# Every node installs ALL THREE affected trains (17 / 21 / 25); only the CPU
# differs, which is the whole lesson:
#
#   vuln-x86     n2-standard-2 (Ice Lake)   x86-64 AVX-512 VBMI   -> EXPOSED
#   safe-arm     c4a-standard-1 (Axion)     ARM64 (no VBMI)       -> NOT EXPOSED
#   safe-intel   n1-standard-1              x86-64 without VBMI   -> NOT EXPOSED
#
# All three are described once in local.nodes (locals.tf); this file just
# iterates that map so adding or retyping a node is a one-line change there.
#
# Each node's startup script is the shared template rendered with that node's
# values. "One startup script per node" is achieved through templatefile()
# rather than three near-identical copies — the nodes differ only in
# architecture, their JDK list, and the expected verdict.
# ================================================================================

resource "google_compute_instance" "node" {
  for_each = local.nodes

  name             = "${local.name}-${each.value.role}"
  machine_type     = each.value.machine
  zone             = var.zone
  min_cpu_platform = each.value.min_cpu

  # Do not boot until egress exists, so the startup script's JDK download has a
  # working route through Cloud NAT from the first second.
  depends_on = [google_compute_router_nat.main]

  # Matches the IAP-only firewall rule in firewall.tf.
  tags = [local.name]

  boot_disk {
    initialize_params {
      image = each.value.image
      size  = 20
      type  = each.value.disk_type
    }
  }

  # Private only — no access_config block means no external IP. IAP TCP
  # forwarding is the only way in; Cloud NAT is the only way out.
  network_interface {
    subnetwork = google_compute_subnetwork.main.id
  }

  # Runs as root on every boot via the guest agent; the script guards itself so
  # the install happens only once (a reboot must not undo ./patch.sh).
  metadata_startup_script = templatefile(
    "${path.module}/scripts/userdata.sh.tftpl", {
      node_role        = each.value.role
      expected_verdict = each.value.expected
      expected_reason  = each.value.reason
      arch             = each.value.arch
      decoder_major    = local.decoder_major
      decoder_port     = var.decoder_port
      deployment_name  = local.name
      # All three affected trains this node installs, one per line as
      # "major|version|url"; the script loops over it and installs each.
      jdks = join("\n", [for j in each.value.jdks : "${j.major}|${j.version}|${j.url}"])
      # The portable detector, injected verbatim so the node runs the exact
      # same script we ship in the repo and viewers run on their own hosts.
      detector = file("${path.module}/../check-exposure.sh")
  })

  labels = {
    role             = each.value.role
    lab              = "java4shell"
    cve              = "cve-2026-114938"
    expected-verdict = lower(replace(each.value.expected, "_", "-"))
  }

  # gcloud compute ssh may write keys into instance metadata; ignore that drift.
  lifecycle {
    ignore_changes = [metadata["ssh-keys"]]
  }
}
