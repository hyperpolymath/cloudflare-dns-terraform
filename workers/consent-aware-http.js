// SPDX-License-Identifier: PMPL-1.0-or-later
// Consent-Aware HTTP Gateway
// Enforces consent before allowing requests to proceed

// Consent levels (aligned with WokeLang philosophy)
const CONSENT_LEVELS = {
  ESSENTIAL: 'essential',       // Required for site to function
  FUNCTIONAL: 'functional',     // Enhances experience
  ANALYTICS: 'analytics',       // Usage tracking
  MARKETING: 'marketing',       // Ads, targeting
  PERSONALIZATION: 'personalization'  // Customization
}

// Resource classifications
const RESOURCE_CONSENT = {
  '/api/analytics': [CONSENT_LEVELS.ANALYTICS],
  '/api/ads': [CONSENT_LEVELS.MARKETING],
  '/api/personalize': [CONSENT_LEVELS.PERSONALIZATION],
  '/api/user/preferences': [CONSENT_LEVELS.FUNCTIONAL],
  // Default: ESSENTIAL (always allowed)
}

addEventListener('fetch', event => {
  event.respondWith(handleConsentAwareRequest(event.request))
})

async function handleConsentAwareRequest(request) {
  const url = new URL(request.url)

  // 1. Check if consent cookie exists
  const consentCookie = getCookie(request, 'user-consent')
  const userConsent = consentCookie ? JSON.parse(decodeURIComponent(consentCookie)) : {}

  // 2. Determine required consent for this resource
  const requiredConsent = getRequiredConsent(url.pathname)

  // 3. Check if user has given required consent
  if (!hasRequiredConsent(userConsent, requiredConsent)) {
    return new Response(JSON.stringify({
      error: 'ConsentRequired',
      message: `This resource requires consent: ${requiredConsent.join(', ')}`,
      required_consent: requiredConsent,
      current_consent: Object.keys(userConsent).filter(k => userConsent[k])
    }), {
      status: 403,
      headers: {
        'Content-Type': 'application/json',
        'X-Consent-Required': requiredConsent.join(','),
        'X-Consent-Gate': 'enforced'
      }
    })
  }

  // 4. Consent granted - proceed with request
  const response = await fetch(request)

  // 5. Add consent headers to response
  const modifiedResponse = new Response(response.body, response)
  modifiedResponse.headers.set('X-Consent-Level', requiredConsent.join(','))
  modifiedResponse.headers.set('X-Consent-Verified', 'true')

  return modifiedResponse
}

function getRequiredConsent(pathname) {
  for (const [pattern, consent] of Object.entries(RESOURCE_CONSENT)) {
    if (pathname.startsWith(pattern)) {
      return consent
    }
  }
  return [CONSENT_LEVELS.ESSENTIAL] // Default
}

function hasRequiredConsent(userConsent, required) {
  return required.every(level => userConsent[level] === true)
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get('Cookie')
  if (!cookieHeader) return null

  const cookies = cookieHeader.split(';').map(c => c.trim())
  const cookie = cookies.find(c => c.startsWith(`${name}=`))
  return cookie ? cookie.split('=')[1] : null
}
