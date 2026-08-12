export default {
  async fetch(request) {
    const url = new URL(request.url)

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders()
      })
    }

    const target = url.searchParams.get("url")
    if (!target) {
      return new Response("Missing ?url=", { status: 400 })
    }

    let targetURL
    try {
      targetURL = new URL(target)
    } catch {
      return new Response("Invalid URL", { status: 400 })
    }

    if (!["http:", "https:"].includes(targetURL.protocol)) {
      return new Response("Only HTTP(S) URLs are supported", { status: 400 })
    }

    // Copy incoming headers, removing proxy/client identity headers.
    const headers = new Headers(request.headers)

    for (const [name] of headers) {
      const n = name.toLowerCase()

      if (
        n === "x-forwarded-for" ||
        n === "x-real-ip" ||
        n === "forwarded" ||
        n.startsWith("cf-")
      ) {
        headers.delete(name)
      }
    }

    // Don't forward the proxy's own Host header.
    headers.delete("host")

    const upstream = await fetch(targetURL, {
      method: request.method,
      headers,
      body: ["GET", "HEAD"].includes(request.method)
        ? undefined
        : request.body,
      redirect: "follow"
    })

    // Copy upstream response headers.
    const responseHeaders = new Headers(upstream.headers)

    // Remove security / framing / isolation headers.
    const strip = [
      "content-security-policy",
      "content-security-policy-report-only",
      "x-frame-options",
      "cross-origin-opener-policy",
      "cross-origin-embedder-policy",
      "cross-origin-resource-policy",
      "origin-agent-cluster",
      "permissions-policy",
      "referrer-policy",
      "x-content-type-options",
      "strict-transport-security",
      "x-xss-protection"
    ]

    for (const name of strip) {
      responseHeaders.delete(name)
    }

    // Remove Cloudflare/tracking headers.
    for (const [name] of responseHeaders) {
      if (name.toLowerCase().startsWith("cf-")) {
        responseHeaders.delete(name)
      }
    }

    // Remove common proxy/server identity headers if desired.
    responseHeaders.delete("server")
    responseHeaders.delete("via")
    responseHeaders.delete("x-powered-by")

    // CORS
    for (const [name, value] of Object.entries(corsHeaders())) {
      responseHeaders.set(name, value)
    }

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: responseHeaders
    })
  }
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "*",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Expose-Headers": "*",
    "Access-Control-Max-Age": "86400"
  }
}
