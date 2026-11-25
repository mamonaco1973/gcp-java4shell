# ================================================================================
# Networking
# One custom-mode VPC with a single private subnet. The three lab nodes have no
# external IP. Outbound (Corretto downloads, apt) goes through Cloud NAT. The
# only inbound path is Google's Identity-Aware Proxy (see firewall.tf) — there is
# no load balancer and no ingress open to the internet anywhere in this stack.
#
#   10.0.0.0/24 — private subnet in var.region (all three nodes)
# ================================================================================

resource "google_compute_network" "main" {
  name                    = "${local.name}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "main" {
  name          = "${local.name}-subnet"
  ip_cidr_range = "10.0.0.0/24"
  region        = var.region
  network       = google_compute_network.main.id

  # Lets the private nodes reach Google APIs without an external IP.
  private_ip_google_access = true
}

# ================================================================================
# Cloud Router + Cloud NAT
# The private nodes route outbound traffic through Cloud NAT to download
# Corretto and Ubuntu packages. Inbound connections cannot be initiated through
# NAT — it is egress-only, which is exactly what an intentionally-vulnerable
# lab wants.
# ================================================================================

resource "google_compute_router" "main" {
  name    = "${local.name}-router"
  region  = var.region
  network = google_compute_network.main.id
}

resource "google_compute_router_nat" "main" {
  name                               = "${local.name}-nat"
  router                             = google_compute_router.main.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}
