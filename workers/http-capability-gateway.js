// SPDX-License-Identifier: MPL-2.0
// HTTP Capability Gateway
// Capability-based security for HTTP requests
// Inspired by WokeLang's capability system

// Capability types
const CAPABILITIES = {
  'file.read': { methods: ['GET'], paths: ['/api/files/*'] },
  'file.write': { methods: ['POST', 'PUT'], paths: ['/api/files/*'] },
  'file.delete': { methods: ['DELETE'], paths: ['/api/files/*'] },
  'user.read': { methods: ['GET'], paths: ['/api/users/*'] },
  'user.write': { methods: ['POST', 'PUT', 'PATCH'], paths: ['/api/users/*'] },
  'analytics.write': { methods: ['POST'], paths: ['/api/analytics/*'] },
  'public.read': { methods: ['GET'], paths: ['/*'] },  // Default capability
}

addEventListener('fetch', event => {
  event.respondWith(handleCapabilityRequest(event.request))
})

async function handleCapabilityRequest(request) {
  const url = new URL(request.url)

  // 1. Extract capability token from header or query param
  const capabilityToken =
    request.headers.get('X-Capability-Token') ||
    url.searchParams.get('capability')

  const requiredCapability = determineRequiredCapability(request.method, url.pathname)

  if (!capabilityToken) {
    // Anonymous access is only valid for routes classified as public.read.
    if (requiredCapability !== 'public.read') {
      return createCapabilityError('NoCapability',
        `Capability token required for ${request.method} ${url.pathname}`, {
          required: requiredCapability
        })
    }

    return forwardRequest(request, requiredCapability, {
      issuer: 'public-anonymous',
      capabilities: ['public.read']
    })
  }

  // 2. Verify and decode capability token
  const capabilities = await verifyCapabilityToken(capabilityToken)
  if (!capabilities) {
    return createCapabilityError('InvalidCapability',
      'Capability token is invalid or expired')
  }

  // 3. Check if request matches any granted capability
  if (!hasCapability(capabilities, requiredCapability)) {
    return createCapabilityError('InsufficientCapability',
      `Missing capability: ${requiredCapability}`, {
        required: requiredCapability,
        granted: capabilities
      })
  }

  return forwardRequest(request, requiredCapability, capabilities)
}

async function forwardRequest(request, requiredCapability, capabilities) {
  const requestHeaders = new Headers(request.headers)
  requestHeaders.set('X-Verified-Capability', requiredCapability)
  requestHeaders.set('X-Capability-Granted-By', capabilities.issuer || 'unknown')

  const modifiedRequest = new Request(request, { headers: requestHeaders })
  const response = await fetch(modifiedRequest)

  const responseHeaders = new Headers(response.headers)
  responseHeaders.set('X-Capability-Used', requiredCapability)
  responseHeaders.set('X-Capability-Gateway', 'enforced')

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders
  })
}

function determineRequiredCapability(method, pathname) {
  for (const [cap, rules] of Object.entries(CAPABILITIES)) {
    if (rules.methods.includes(method) &&
        rules.paths.some(pattern => matchPath(pathname, pattern))) {
      return cap
    }
  }
  return 'public.read'
}

function matchPath(pathname, pattern) {
  // Simple glob matching
  const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$')
  return regex.test(pathname)
}

function hasCapability(grantedCaps, required) {
  if (!grantedCaps || !grantedCaps.capabilities) return false
  return grantedCaps.capabilities.includes(required)
}

async function verifyCapabilityToken(token) {
  if (!token) return null

  try {
    // In production: verify JWT signature
    // For now: decode base64 JSON
    const decoded = JSON.parse(atob(token))

    // Check expiration
    if (decoded.exp && decoded.exp < Date.now() / 1000) {
      return null
    }

    return decoded
  } catch (e) {
    return null
  }
}

function createCapabilityError(code, message, details = {}) {
  return new Response(JSON.stringify({
    error: code,
    message: message,
    ...details,
    hint: 'Include X-Capability-Token header with valid capability token'
  }), {
    status: 403,
    headers: {
      'Content-Type': 'application/json',
      'X-Capability-Error': code,
      'WWW-Authenticate': 'Capability realm="API"'
    }
  })
}

// Capability token generator (for backend to call)
// POST /api/generate-capability
async function generateCapabilityToken(capabilities, expiresIn = 3600) {
  const token = {
    capabilities: capabilities,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + expiresIn,
    issuer: 'wokelang-gateway'
  }

  // In production: sign with HMAC/RSA
  return btoa(JSON.stringify(token))
}
