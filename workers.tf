# SPDX-License-Identifier: PMPL-1.0-or-later
# Cloudflare Workers Configuration - Optimized for FREE Tier
#
# FREE TIER: 100,000 requests/day (3 million/month)
# COST OPTIMIZATION:
# - Transform Rules (security headers) = FREE unlimited ✅
# - Workers only on specific routes that need advanced logic ✅
# - Avoid deploying workers on high-traffic routes ✅

# ============================================================================
# WORKER SCRIPTS (Upload to Cloudflare)
# ============================================================================

# These need to be deployed via wrangler CLI:
# $ cd workers/
# $ wrangler deploy consent-aware-http.js
# $ wrangler deploy http-capability-gateway.js

# ============================================================================
# WORKER ROUTES (Optional - Only deploy if needed)
# ============================================================================

# CONSENT GATE - Only on routes that require consent
# Typical usage: Analytics, tracking, personalization endpoints
# Estimated requests: ~1-5% of total traffic
resource "cloudflare_worker_route" "consent_gate" {
  for_each = { for k, v in local.domains : k => v if v.enable_consent_gate }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id

  # Only apply to specific paths that need consent
  pattern = "${each.value.domain}/api/analytics/*"

  script_name = "consent-aware-http"
}

resource "cloudflare_worker_route" "consent_gate_tracking" {
  for_each = { for k, v in local.domains : k => v if v.enable_consent_gate }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id
  pattern = "${each.value.domain}/api/tracking/*"
  script_name = "consent-aware-http"
}

# CAPABILITY GATE - Only on API endpoints
# Typical usage: Protected API calls
# Estimated requests: ~0.1-1% of total traffic
resource "cloudflare_worker_route" "capability_gate_api" {
  for_each = { for k, v in local.domains : k => v if v.enable_capability_gate }

  zone_id = data.cloudflare_zones.all[each.key].zones[0].id

  # Only apply to API routes that need capabilities
  pattern = "${each.value.domain}/api/*"

  script_name = "http-capability-gateway"
}

# ============================================================================
# COST ESTIMATION
# ============================================================================

# Typical website traffic breakdown:
# - Static pages (HTML, CSS, JS, images): 80-90% of requests → FREE (Transform Rules)
# - Analytics/tracking: 5-10% → Consent Worker (still within free tier)
# - Protected API calls: 1-5% → Capability Worker (still within free tier)
#
# Example site with 50,000 requests/day:
# - Static (40,000): FREE via Transform Rules
# - Analytics (5,000): FREE via Consent Worker
# - API (5,000): FREE via Capability Worker
# Total: 50,000/day = 1.5M/month → Well within FREE tier (3M/month)
#
# You'd need ~100,000 requests/day to approach free tier limit
# That's approximately 1 million page views/month for typical sites

# ============================================================================
# ALTERNATIVE: Use _headers file for Cloudflare Pages (FREE unlimited)
# ============================================================================

# If using Cloudflare Pages, security headers via _headers file is FREE
# No workers needed at all!
# See: examples/_headers

# ============================================================================
# MONITORING (Prevent unexpected charges)
# ============================================================================

# Set up notification if approaching limits:
# https://dash.cloudflare.com/[account]/notifications
#
# Recommended thresholds:
# - Alert at 80,000 requests/day (80% of free tier)
# - Alert at 90,000 requests/day (90% of free tier)
