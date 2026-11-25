# ================================================================================
# Firewall
# A custom VPC denies all ingress by default. The ONE allow rule admits Google's
# Identity-Aware Proxy range (35.235.240.0/20) — and nothing else — so the nodes
# are reachable only through `gcloud compute ssh --tunnel-through-iap` and
# `gcloud compute start-iap-tunnel`, both of which require an authenticated
# Google identity with IAP access. Nothing on the internet, and nothing else in
# the VPC, can open a connection to these instances.
#
#   22    SSH — operator access and the scripts' remote commands
#   80    the verdict page (apache2)
#   8080  the sample Base64 decode service (the exposure surface)
#
# This closed posture is deliberate for an intentionally-vulnerable lab: the
# only thing that should ever drive the vulnerable decoder is your own PoC, run
# through an IAP tunnel you open.
# ================================================================================

resource "google_compute_firewall" "iap" {
  name    = "${local.name}-allow-iap"
  network = google_compute_network.main.id

  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]
  target_tags   = [local.name]

  allow {
    protocol = "tcp"
    ports    = ["22", "80", tostring(var.decoder_port)]
  }
}
