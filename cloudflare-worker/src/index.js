export default {
  async fetch(request, env) {
    // Only allow POST requests.
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: { Allow: "POST" },
      });
    }

    // Validate upstream configuration.
    if (!env.UPSTREAM_URL) {
      return new Response("UPSTREAM_URL is not configured", { status: 500 });
    }
    const incoming = new URL(request.url);
    const upstream = new URL(env.UPSTREAM_URL);

    // Require HTTPS.
    if (upstream.protocol !== "https:") {
      return new Response("Upstream must use HTTPS", { status: 500 });
    }

    // Preserve path and query parameters for request signatures.
    upstream.pathname = incoming.pathname;
    upstream.search = incoming.search;
    try {
      const proxyRequest = new Request(upstream.toString(), request);
      return await fetch(proxyRequest, { redirect: "manual" });
    } catch (error) {
      console.error("Upstream request failed:", error);
      return new Response("Bad Gateway", { status: 502 });
    }
  },
};
