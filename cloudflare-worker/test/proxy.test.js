import assert from "node:assert/strict";
import { test, mock } from "node:test";
import worker from "../src/index.js";

const env = { UPSTREAM_URL: "https://relay.example.org/ignored?old=1" };

for (const method of ["GET", "PUT", "DELETE", "OPTIONS"]) {
  test(`${method} is rejected`, async () => {
    const response = await worker.fetch(new Request("https://push.family-vpn.workers.dev/push", { method }), env);
    assert.equal(response.status, 405);
    assert.equal(response.headers.get("Allow"), "POST");
  });
}

test("missing upstream and non-HTTPS upstream are rejected", async () => {
  for (const settings of [{}, { UPSTREAM_URL: "http://relay.example.org" }]) {
    const response = await worker.fetch(new Request("https://push.family-vpn.workers.dev/push", { method: "POST" }), settings);
    assert.equal(response.status, 500);
  }
});

test("signed bytes, paths, queries and headers survive forwarding; redirects are not followed", async () => {
  const payload = '{"server":"vpn.example.org", "command":null}';
  const headers = {
    "Content-Type": "application/json",
    Authorization: "Bearer synthetic-enrollment",
    "X-Relay-Time": "1234567890",
    "X-Relay-Nonce": "synthetic-nonce",
    "X-Relay-Signature": "synthetic-signature",
  };
  const upstreamResponse = new Response("rate limit", { status: 429, headers: { "Retry-After": "60" } });
  const stub = mock.method(globalThis, "fetch", async (request, options) => {
    assert.equal(request.url, "https://relay.example.org/endpoints?test=1");
    assert.equal(request.method, "POST");
    assert.equal(await request.text(), payload);
    for (const [key, value] of Object.entries(headers)) assert.equal(request.headers.get(key), value);
    assert.equal(options.redirect, "manual");
    return upstreamResponse;
  });
  try {
    const request = new Request("https://push.family-vpn.workers.dev/endpoints?test=1", { method: "POST", headers, body: payload });
    const response = await worker.fetch(request, env);
    assert.equal(response, upstreamResponse);
    assert.equal(response.status, 429);
    assert.equal(response.headers.get("Retry-After"), "60");
  } finally {
    stub.mock.restore();
  }
});

test("network failures become 502", async () => {
  const stub = mock.method(globalThis, "fetch", async () => { throw new Error("synthetic network failure"); });
  const logs = mock.method(console, "error", () => {});
  try {
    const response = await worker.fetch(new Request("https://push.family-vpn.workers.dev/push", { method: "POST", body: "{}" }), env);
    assert.equal(response.status, 502);
  } finally {
    stub.mock.restore();
    logs.mock.restore();
  }
});
