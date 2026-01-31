// SPDX-License-Identifier: PMPL-1.0-or-later
// Cloudflare Worker to inject security headers
// Deploy via: wrangler deploy

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

const SECURITY_HEADERS = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=()',
  'X-XSS-Protection': '1; mode=block',
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
}

async function handleRequest(request) {
  // Fetch from origin (GitHub Pages)
  const response = await fetch(request)

  // Clone response so we can modify headers
  const modifiedResponse = new Response(response.body, response)

  // Add security headers
  Object.entries(SECURITY_HEADERS).forEach(([key, value]) => {
    modifiedResponse.headers.set(key, value)
  })

  // Add custom header to verify worker is running
  modifiedResponse.headers.set('X-Secured-By', 'Cloudflare-Worker')

  return modifiedResponse
}
