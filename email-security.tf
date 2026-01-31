# SPDX-License-Identifier: PMPL-1.0-or-later
# Email security records: DKIM, DMARC, SPF, BIMI, ARC

# ============================================================================
# DKIM (DomainKeys Identified Mail)
# ============================================================================

resource "cloudflare_record" "dkim" {
  for_each = { for k, v in local.domains : k => v if v.enable_mail && v.dkim_selector != "" }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "${each.value.dkim_selector}._domainkey"
  content = "v=DKIM1; k=rsa; p=${each.value.dkim_public_key}"
  type    = "TXT"
  comment = "DKIM public key (${each.value.dkim_selector})"
}

# Multiple DKIM selectors (for rotation)
resource "cloudflare_record" "dkim_rotation" {
  for_each = { for k, v in local.domains : k => v if v.enable_mail && v.dkim_selector_rotation != "" }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "${each.value.dkim_selector_rotation}._domainkey"
  content = "v=DKIM1; k=rsa; p=${each.value.dkim_public_key_rotation}"
  type    = "TXT"
  comment = "DKIM rotation key"
}

# ============================================================================
# BIMI (Brand Indicators for Message Identification)
# ============================================================================

resource "cloudflare_record" "bimi" {
  for_each = { for k, v in local.domains : k => v if v.enable_mail && v.bimi_logo_url != "" }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "default._bimi"
  content = "v=BIMI1; l=${each.value.bimi_logo_url}; a=${each.value.bimi_vmc_url}"
  type    = "TXT"
  comment = "BIMI logo for email"
}

# ============================================================================
# ARC (Authenticated Received Chain)
# ============================================================================

resource "cloudflare_record" "arc" {
  for_each = { for k, v in local.domains : k => v if v.enable_mail && v.arc_selector != "" }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "${each.value.arc_selector}._arc"
  content = "v=ARC1; k=rsa; p=${each.value.arc_public_key}"
  type    = "TXT"
  comment = "ARC signing key"
}

# ============================================================================
# Enhanced CAA with Critical Flag (128)
# ============================================================================

resource "cloudflare_record" "caa_critical_letsencrypt" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "@"
  type    = "CAA"

  data {
    flags = "128"  # Critical flag
    tag   = "issue"
    value = "letsencrypt.org"
  }

  comment = "CAA - Let's Encrypt (CRITICAL)"
}

resource "cloudflare_record" "caa_critical_digicert" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "@"
  type    = "CAA"

  data {
    flags = "128"  # Critical flag
    tag   = "issue"
    value = "digicert.com"
  }

  comment = "CAA - DigiCert (CRITICAL)"
}

resource "cloudflare_record" "caa_wildcard" {
  for_each = local.domains

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "@"
  type    = "CAA"

  data {
    flags = "128"
    tag   = "issuewild"
    value = "letsencrypt.org"
  }

  comment = "CAA - Wildcard cert authorization (CRITICAL)"
}

# ============================================================================
# ADSP (Author Domain Signing Practices) - Legacy but some use
# ============================================================================

resource "cloudflare_record" "adsp" {
  for_each = { for k, v in local.domains : k => v if v.enable_mail }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "_adsp._domainkey"
  content = "dkim=all"
  type    = "TXT"
  comment = "ADSP - All mail must be DKIM signed"
}

# ============================================================================
# Sender Policy Framework (SPF) - Enhanced
# ============================================================================

# Already defined in main.tf, but here's the enhanced version if using mail:
resource "cloudflare_record" "spf_mail" {
  for_each = { for k, v in local.domains : k => v if v.enable_mail && v.mx_primary != "" }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "@"
  content = "v=spf1 mx include:_spf.github.com include:${each.value.spf_include} ~all"
  type    = "TXT"
  comment = "SPF - Enhanced for mail servers"
}

# ============================================================================
# Mail Submission (Submission port)
# ============================================================================

resource "cloudflare_record" "submission" {
  for_each = { for k, v in local.domains : k => v if v.enable_mail && v.mx_primary != "" }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "_submission._tcp"
  type    = "SRV"

  data {
    service  = "_submission"
    proto    = "_tcp"
    name     = each.value.domain
    priority = 0
    weight   = 1
    port     = 587
    target   = each.value.mx_primary
  }

  comment = "Mail submission (port 587)"
}

# ============================================================================
# IMAP/POP3 SRV Records
# ============================================================================

resource "cloudflare_record" "imaps" {
  for_each = { for k, v in local.domains : k => v if v.enable_mail && v.mx_primary != "" }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "_imaps._tcp"
  type    = "SRV"

  data {
    service  = "_imaps"
    proto    = "_tcp"
    name     = each.value.domain
    priority = 0
    weight   = 1
    port     = 993
    target   = each.value.mx_primary
  }

  comment = "IMAP over TLS (port 993)"
}

resource "cloudflare_record" "pop3s" {
  for_each = { for k, v in local.domains : k => v if v.enable_mail && v.mx_primary != "" }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "_pop3s._tcp"
  type    = "SRV"

  data {
    service  = "_pop3s"
    proto    = "_tcp"
    name     = each.value.domain
    priority = 0
    weight   = 1
    port     = 995
    target   = each.value.mx_primary
  }

  comment = "POP3 over TLS (port 995)"
}

# ============================================================================
# Autoconfig/Autodiscover (Email client configuration)
# ============================================================================

resource "cloudflare_record" "autoconfig" {
  for_each = { for k, v in local.domains : k => v if v.enable_mail }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "autoconfig"
  content = each.value.domain
  type    = "CNAME"
  proxied = true
  comment = "Email autoconfig (Thunderbird, etc.)"
}

resource "cloudflare_record" "autodiscover" {
  for_each = { for k, v in local.domains : k => v if v.enable_mail }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  name    = "autodiscover"
  content = each.value.domain
  type    = "CNAME"
  proxied = true
  comment = "Email autodiscover (Outlook, etc.)"
}
