export default {
  async fetch(request, env) {
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: { Allow: "POST" },
      });
    }
    const incoming = new URL(request.url);
    if (!["/endpoints", "/rotate", "/push"].includes(incoming.pathname)) {
      return new Response("Not Found", { status: 404 });
    }
    if (!env.UPSTREAM_URL || !env.RELAY_PROXY_TOKEN) {
      return new Response("Proxy is not configured", { status: 503 });
    }
    let upstream;
    try {
      upstream = new URL(env.UPSTREAM_URL);
      if (upstream.protocol !== "https:" || upstream.username || upstream.password || upstream.search || upstream.hash) {
        throw new Error("Invalid upstream");
      }
    } catch {
      return new Response("Invalid upstream configuration", { status: 500 });
    }
    // Allow UPSTREAM_URL to be the HA REST base, including its proxy prefix.
    upstream.pathname = upstream.pathname.replace(/\/$/, "") + incoming.pathname;
    upstream.search = incoming.search;
    try {
      const proxyRequest = new Request(upstream.toString(), request);
      // Replace any caller-supplied value. Never expose this Worker secret to clients.
      proxyRequest.headers.set("X-Relay-Proxy-Token", env.RELAY_PROXY_TOKEN);
      proxyRequest.headers.set("Host", upstream.host);
      const response = await fetch(proxyRequest, { redirect: "manual" });
      const safeResponse = new Response(response.body, response);
      safeResponse.headers.delete("X-Relay-Proxy-Token");
      safeResponse.headers.set("Cache-Control", "no-store");
      return safeResponse;
    } catch {
      console.error("Upstream relay request failed");
      return new Response("Bad Gateway", { status: 502 });
    }
  },
};
