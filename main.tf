# SPDX-License-Identifier: PMPL-1.0-or-later
# Cloudflare DNS Management via Terraform
# Manages DNS records for all hyperpolymath domains

terraform {
  required_version = ">= 1.0"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

# Read domains from CSV
locals {
  domains_raw = csvdecode(file("${path.module}/domains.csv"))

  # Parse domains into structured data
  domains = {
    for d in local.domains_raw : d.domain => {
      domain                    = d.domain
      github_user               = d.github_user
      github_repo               = d.github_repo
      tunnel_id                 = d.tunnel_id
      mx_primary                = d.mx_primary
      mx_secondary              = d.mx_secondary
      admin_email               = d.admin_email
      ssh_fp_sha256             = d.ssh_fp_sha256
      ssh_fp_sha256_backup      = d.ssh_fp_sha256_backup
      dkim_selector             = d.dkim_selector
      dkim_public_key           = try(d.dkim_public_key, "")
      dkim_selector_rotation    = try(d.dkim_selector_rotation, "")
      dkim_public_key_rotation  = try(d.dkim_public_key_rotation, "")
      bimi_logo_url             = try(d.bimi_logo_url, "")
      bimi_vmc_url              = try(d.bimi_vmc_url, "")
      arc_selector              = try(d.arc_selector, "")
      arc_public_key            = try(d.arc_public_key, "")
      spf_include               = try(d.spf_include, "")
      tlsa_cert_hash            = d.tlsa_cert_hash
      enable_mail               = tobool(d.enable_mail)
      enable_tunnel             = tobool(d.enable_tunnel)
      enable_ssh                = tobool(d.enable_ssh)
      enable_github_pages       = tobool(d.enable_github_pages)
      pages_project             = d.pages_project
    }
  }
}

# Get zone IDs for all domains
data "cloudflare_zones" "all" {
  for_each = local.domains
  filter {
    name = each.value.domain
  }
}

# ============================================================================
# CORE RECORDS (CNAME)
# ============================================================================

resource "cloudflare_record" "www" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "www"
  content = each.value.domain
  type    = "CNAME"
  proxied = true
  comment = "www subdomain (proxied)"
}

resource "cloudflare_record" "static" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "static"
  content = each.value.domain
  type    = "CNAME"
  proxied = true
  comment = "Static assets CDN"
}

resource "cloudflare_record" "assets" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "assets"
  content = each.value.domain
  type    = "CNAME"
  proxied = true
  comment = "Assets subdomain"
}

resource "cloudflare_record" "cdn" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "cdn"
  content = each.value.domain
  type    = "CNAME"
  proxied = true
  comment = "CDN subdomain"
}

# ============================================================================
# GITHUB PAGES
# ============================================================================

resource "cloudflare_record" "gh_pages" {
  for_each = { for k, v in local.domains : k => v if v.enable_github_pages }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "gh-pages"
  content = "${each.value.github_user}.github.io"
  type    = "CNAME"
  proxied = false
  comment = "GitHub Pages (NOT proxied)"
}

# ============================================================================
# CLOUDFLARE PAGES
# ============================================================================

resource "cloudflare_pages_domain" "main" {
  for_each = { for k, v in local.domains : k => v if v.pages_project != "" }

  account_id   = var.cloudflare_account_id
  project_name = each.value.pages_project
  domain       = each.value.domain
}

resource "cloudflare_pages_domain" "www" {
  for_each = { for k, v in local.domains : k => v if v.pages_project != "" }

  account_id   = var.cloudflare_account_id
  project_name = each.value.pages_project
  domain       = "www.${each.value.domain}"
}

# ============================================================================
# SECURITY RECORDS (SPF, DMARC, CAA)
# ============================================================================

resource "cloudflare_record" "spf" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "@"
  content = "v=spf1 include:_spf.github.com ~all"
  type    = "TXT"
  comment = "SPF record (GitHub Pages)"
}

resource "cloudflare_record" "dmarc" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "_dmarc"
  content = "v=DMARC1; p=reject; rua=mailto:${each.value.admin_email}"
  type    = "TXT"
  comment = "DMARC policy"
}

resource "cloudflare_record" "caa_letsencrypt" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "@"
  type    = "CAA"

  data {
    flags = "0"
    tag   = "issue"
    value = "letsencrypt.org"
  }

  comment = "CAA - Let's Encrypt"
}

resource "cloudflare_record" "caa_digicert" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "@"
  type    = "CAA"

  data {
    flags = "0"
    tag   = "issue"
    value = "digicert.com"
  }

  comment = "CAA - DigiCert (fallback)"
}

resource "cloudflare_record" "caa_iodef" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "@"
  type    = "CAA"

  data {
    flags = "0"
    tag   = "iodef"
    value = "mailto:${each.value.admin_email}"
  }

  comment = "CAA - Incident reporting"
}

# ============================================================================
# MAIL RECORDS (MX, MTA-STS, TLS-RPT)
# ============================================================================

resource "cloudflare_record" "mx_primary" {
  for_each = { for k, v in local.domains : k => v if v.enable_mail && v.mx_primary != "" }

  zone_id  = data.cloudflare_zones.all[each.key].zones[0].id
  name     = "@"
  content  = each.value.mx_primary
  type     = "MX"
  priority = 10
  comment  = "Primary mail server"
}

resource "cloudflare_record" "mx_secondary" {
  for_each = { for k, v in local.domains : k => v if v.enable_mail && v.mx_secondary != "" }

  zone_id  = data.cloudflare_zones.all[each.key].zones[0].id
  name     = "@"
  content  = each.value.mx_secondary
  type     = "MX"
  priority = 20
  comment  = "Secondary mail server"
}

resource "cloudflare_record" "mta_sts" {
  for_each = { for k, v in local.domains : k => v if v.enable_mail }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "_mta-sts"
  content = "v=STSv1; id=2026013101; mode=enforce"
  type    = "TXT"
  comment = "MTA-STS policy"
}

resource "cloudflare_record" "tls_rpt" {
  for_each = { for k, v in local.domains : k => v if v.enable_mail }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "_smtp._tls"
  content = "v=TLSRPTv1; rua=mailto:tls-rpt@${each.value.domain}"
  type    = "TXT"
  comment = "TLS reporting"
}

# ============================================================================
# SSH FINGERPRINTS (SSHFP)
# ============================================================================

resource "cloudflare_record" "sshfp_sha256" {
  for_each = { for k, v in local.domains : k => v if v.enable_ssh && v.ssh_fp_sha256 != "" }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "@"
  type    = "SSHFP"

  data {
    algorithm   = 1
    type        = 2
    fingerprint = each.value.ssh_fp_sha256
  }

  comment = "SSH fingerprint (RSA SHA256)"
}

resource "cloudflare_record" "sshfp_sha256_backup" {
  for_each = { for k, v in local.domains : k => v if v.enable_ssh && v.ssh_fp_sha256_backup != "" }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "@"
  type    = "SSHFP"

  data {
    algorithm   = 2
    type        = 2
    fingerprint = each.value.ssh_fp_sha256_backup
  }

  comment = "SSH fingerprint backup (ECDSA SHA256)"
}

# ============================================================================
# ZERO TRUST / CLOUDFLARE TUNNEL
# ============================================================================

resource "cloudflare_record" "tunnel_dashboard" {
  for_each = { for k, v in local.domains : k => v if v.enable_tunnel && v.tunnel_id != "" }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "dashboard.internal"
  content = "${each.value.tunnel_id}.cfargotunnel.com"
  type    = "CNAME"
  proxied = false
  comment = "Zero Trust - Internal dashboard"
}

resource "cloudflare_record" "tunnel_ci" {
  for_each = { for k, v in local.domains : k => v if v.enable_tunnel && v.tunnel_id != "" }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "ci.internal"
  content = "${each.value.tunnel_id}.cfargotunnel.com"
  type    = "CNAME"
  proxied = false
  comment = "Zero Trust - CI/CD access"
}

resource "cloudflare_record" "tunnel_db" {
  for_each = { for k, v in local.domains : k => v if v.enable_tunnel && v.tunnel_id != "" }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "db.internal"
  content = "${each.value.tunnel_id}.cfargotunnel.com"
  type    = "CNAME"
  proxied = false
  comment = "Zero Trust - Database access"
}

# ============================================================================
# COMMUNICATION SUBDOMAINS
# ============================================================================

resource "cloudflare_record" "discourse" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "discourse"
  content = each.value.domain
  type    = "CNAME"
  proxied = true
  comment = "Discourse forum"
}

resource "cloudflare_record" "zulip" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "zulip"
  content = each.value.domain
  type    = "CNAME"
  proxied = true
  comment = "Zulip chat"
}

resource "cloudflare_record" "members" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "members"
  content = each.value.domain
  type    = "CNAME"
  proxied = true
  comment = "Members area"
}

# ============================================================================
# AUTOMATION & MONITORING
# ============================================================================

resource "cloudflare_record" "ci" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "ci"
  content = each.value.domain
  type    = "CNAME"
  proxied = true
  comment = "CI/CD status"
}

resource "cloudflare_record" "status" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "status"
  content = each.value.domain
  type    = "CNAME"
  proxied = true
  comment = "Public status page"
}

resource "cloudflare_record" "logs" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "logs"
  content = each.value.domain
  type    = "CNAME"
  proxied = true
  comment = "Log aggregation"
}

# ============================================================================
# API & SECURITY
# ============================================================================

resource "cloudflare_record" "api" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "api"
  content = each.value.domain
  type    = "CNAME"
  proxied = true
  comment = "API gateway (WASM fronted)"
}

resource "cloudflare_record" "auth" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "auth"
  content = each.value.domain
  type    = "CNAME"
  proxied = true
  comment = "Authentication service"
}

resource "cloudflare_record" "wasm" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "wasm"
  content = each.value.domain
  type    = "CNAME"
  proxied = true
  comment = "WASM proxy endpoint"
}

# ============================================================================
# EXTERNAL INTEGRATIONS
# ============================================================================

resource "cloudflare_record" "linkedin" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "linkedin"
  content = each.value.domain
  type    = "CNAME"
  proxied = true
  comment = "LinkedIn showcase"
}

resource "cloudflare_record" "rss" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "rss"
  content = each.value.domain
  type    = "CNAME"
  proxied = true
  comment = "RSS feed aggregator"
}
