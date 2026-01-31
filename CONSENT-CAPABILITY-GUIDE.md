# Consent-Aware HTTP & Capability Gateway Implementation Guide

## Overview

Both `consent-aware-http` and `http-capability-gateway` are **absolutely realistic** and can be deployed to your sites via Cloudflare Workers.

## Architecture

```
User Request
    ↓
Cloudflare Edge
    ↓
[Consent Gate] ← Checks user consent cookie
    ↓ (if consent granted)
[Capability Gate] ← Verifies capability token
    ↓ (if capability valid)
Origin Server (GitHub Pages / Cloudflare Pages)
    ↓
Response (with audit headers)
```

---

## 1. Consent-Aware HTTP

### What It Does:
- Blocks requests to resources that require specific consent
- Returns 403 with required consent levels if not granted
- Enforces GDPR/privacy compliance at HTTP layer
- Integrates with WokeLang's `only if okay` philosophy

### Use Cases:
```javascript
// Analytics API - requires analytics consent
GET /api/analytics/track
→ 403 if user hasn't consented to analytics

// Personalization - requires personalization consent
GET /api/personalize/recommendations
→ 403 if user hasn't consented to personalization

// Essential resources - always allowed
GET /api/content
→ 200 (essential, no consent needed)
```

### Setting User Consent:

**Frontend JavaScript:**
```javascript
// User accepts consent via UI
function setConsent(levels) {
  const consent = {
    essential: true,      // Always true
    functional: levels.functional || false,
    analytics: levels.analytics || false,
    marketing: levels.marketing || false,
    personalization: levels.personalization || false
  };

  // Set cookie
  document.cookie = `user-consent=${encodeURIComponent(JSON.stringify(consent))}; max-age=31536000; path=/; secure; samesite=strict`;

  // Refresh page to apply new consent
  location.reload();
}
```

**Consent UI Example:**
```html
<div class="consent-banner">
  <h3>Cookie Consent</h3>
  <p>Choose what data you're comfortable sharing:</p>

  <label>
    <input type="checkbox" checked disabled> Essential (required)
  </label>
  <label>
    <input type="checkbox" id="functional"> Functional features
  </label>
  <label>
    <input type="checkbox" id="analytics"> Anonymous analytics
  </label>
  <label>
    <input type="checkbox" id="marketing"> Marketing
  </label>
  <label>
    <input type="checkbox" id="personalization"> Personalization
  </label>

  <button onclick="saveConsent()">Save Preferences</button>
</div>
```

### Deployment:

```bash
cd workers/
wrangler deploy consent-aware-http.js --name consent-gate
wrangler route add wokelang.org/* consent-gate
```

---

## 2. HTTP Capability Gateway

### What It Does:
- Enforces capability-based security at HTTP layer
- Prevents privilege escalation attacks
- Implements WokeLang's capability model for web APIs
- Supports fine-grained access control

### Use Cases:

```javascript
// Generate capability token (backend)
const token = generateCapability({
  capabilities: ['file.read', 'user.read'],
  expiresIn: 3600  // 1 hour
});

// Client uses token
fetch('/api/files/document.pdf', {
  headers: {
    'X-Capability-Token': token
  }
})
→ 200 (has file.read capability)

// Attempt to delete without capability
fetch('/api/files/document.pdf', {
  method: 'DELETE',
  headers: {
    'X-Capability-Token': token  // Only has read, not delete
  }
})
→ 403 (missing file.delete capability)
```

### Capability Token Format:

```json
{
  "capabilities": ["file.read", "user.read"],
  "iat": 1706745600,
  "exp": 1706749200,
  "issuer": "wokelang-gateway",
  "subject": "user-123"
}
```

### Backend Integration:

**Generate capability token (Node.js/Deno):**
```javascript
import jwt from 'jsonwebtoken';

function generateCapabilityToken(userId, capabilities, expiresIn = '1h') {
  return jwt.sign({
    capabilities: capabilities,
    subject: userId,
    issuer: 'wokelang-api'
  }, process.env.CAPABILITY_SECRET, {
    expiresIn: expiresIn,
    algorithm: 'HS256'
  });
}

// Example
const token = generateCapabilityToken('user-123', [
  'file.read',
  'file.write',
  'user.read'
]);
```

### Deployment:

```bash
wrangler deploy http-capability-gateway.js --name capability-gate
wrangler route add wokelang.org/api/* capability-gate
```

---

## 3. Combined Deployment (Consent + Capability)

You can **chain both workers** for maximum security:

```
Request
  ↓
1. Consent Gate (checks consent cookie)
  ↓
2. Capability Gate (checks capability token)
  ↓
Origin
```

**Terraform Configuration:**

```hcl
# In main.tf
resource "cloudflare_worker_route" "consent_gate" {
  for_each = local.domains

  zone_id     = data.cloudflare_zones.all[each.key].zones[0].id
  pattern     = "${each.value.domain}/*"
  script_name = "consent-aware-http"
}

resource "cloudflare_worker_route" "capability_gate" {
  for_each = local.domains

  zone_id     = data.cloudflare_zones.all[each.key].zones[0].id
  pattern     = "${each.value.domain}/api/*"
  script_name = "http-capability-gateway"
}
```

---

## 4. Integration with WokeLang

These workers are **perfect** for WokeLang-powered sites:

### WokeLang Backend:
```woke
// WokeLang API endpoint
to handleRequest(request: HttpRequest) {
  // Capability already verified by gateway
  remember caps = request.headers["X-Verified-Capability"]

  // Check capability in WokeLang
  consent for caps {
    // Capability granted - proceed
    return serveFile(request.path)
  } or {
    // Should never reach here (gateway blocks)
    return error("Capability required")
  }
}
```

### Frontend (ReScript):
```rescript
// consent-ui.res
@react.component
let make = () => {
  let (consent, setConsent) = React.useState(_ => None)

  let saveConsent = levels => {
    // Call consent-aware-http to set cookie
    Fetch.post("/api/consent", {
      "essential": true,
      "functional": levels.functional,
      "analytics": levels.analytics,
      "marketing": levels.marketing,
      "personalization": levels.personalization,
    })
    ->Promise.then(_ => {
      setConsent(_ => Some(levels))
      Promise.resolve()
    })
    ->ignore
  }

  <ConsentBanner onSave={saveConsent} />
}
```

---

## 5. Real-World Example: wokelang.org

### Setup:

1. **Deploy Workers:**
```bash
cd /var/mnt/eclipse/repos/cloudflare-dns-terraform/workers
wrangler deploy consent-aware-http.js
wrangler deploy http-capability-gateway.js
```

2. **Configure Routes:**
```bash
# Consent gate on all pages
wrangler route add "wokelang.org/*" consent-aware-http

# Capability gate on APIs
wrangler route add "wokelang.org/api/*" http-capability-gateway
```

3. **Update Terraform:**
```bash
terraform apply  # Adds routes automatically
```

### Testing:

```bash
# Test consent gate
curl -I https://wokelang.org/api/analytics
# → 403 Consent Required (if no consent cookie)

# Set consent
curl -b "user-consent=%7B%22analytics%22%3Atrue%7D" \
  https://wokelang.org/api/analytics
# → 200 OK

# Test capability gate
curl https://wokelang.org/api/files/test.txt
# → 403 Missing capability

curl -H "X-Capability-Token: eyJ..." \
  https://wokelang.org/api/files/test.txt
# → 200 OK (if token has file.read)
```

---

## 6. Advanced Features

### A. Capability Delegation

```javascript
// Parent capability can create child capabilities
const parentToken = generateCapability({
  capabilities: ['file.read', 'file.write'],
  canDelegate: true
});

// Create delegated token with fewer capabilities
const childToken = delegateCapability(parentToken, {
  capabilities: ['file.read'],  // Subset only
  expiresIn: 600  // Shorter lifetime
});
```

### B. Consent Granularity

```javascript
// Per-resource consent
const RESOURCE_CONSENT = {
  '/api/analytics/pageviews': ['analytics'],
  '/api/analytics/heatmaps': ['analytics', 'functional'],
  '/api/ads/targeting': ['marketing', 'personalization'],
}
```

### C. Audit Logging

```javascript
// Log all capability usage
async function auditCapabilityUse(capability, user, resource) {
  await fetch('https://logs.wokelang.org/audit', {
    method: 'POST',
    body: JSON.stringify({
      timestamp: Date.now(),
      capability: capability,
      user: user,
      resource: resource
    })
  });
}
```

---

## 7. Summary

### Is it realistic? **ABSOLUTELY YES!**

✅ **Consent-Aware HTTP:**
- Simple to implement (cookie-based)
- GDPR/privacy compliant
- Works with Cloudflare Workers
- Integrates with any frontend

✅ **HTTP Capability Gateway:**
- Proven pattern (used by Google, Cloudflare, etc.)
- More secure than role-based access control
- Perfect for microservices
- Prevents privilege escalation

### Next Steps:

1. **Test workers locally:**
```bash
wrangler dev consent-aware-http.js
```

2. **Deploy to wokelang.org:**
```bash
wrangler deploy
```

3. **Integrate with WokeLang SSG:**
- Add consent UI to site footer
- Generate capability tokens from WokeLang backend
- Add audit logging

**Your sites will have world-class security AND privacy!** 🔒🚀
