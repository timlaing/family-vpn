import assert from "node:assert/strict";
import { test, mock } from "node:test";
import worker from "../src/index.js";

const env = { UPSTREAM_URL: "https://relay.example.org/family-vpn", RELAY_PROXY_TOKEN: "synthetic-worker-secret" };

for (const method of ["GET", "PUT", "DELETE", "OPTIONS"]) {
  test(`${method} is rejected`, async () => {
    const response = await worker.fetch(new Request("https://push.family-vpn.workers.dev/push", { method }), env);
    assert.equal(response.status, 405);
    assert.equal(response.headers.get("Allow"), "POST");
  });
}

test("missing upstream and non-HTTPS upstream are rejected", async () => {
  for (const settings of [{}, { UPSTREAM_URL: "http://relay.example.org", RELAY_PROXY_TOKEN: env.RELAY_PROXY_TOKEN }]) {
    const response = await worker.fetch(new Request("https://push.family-vpn.workers.dev/push", { method: "POST" }), settings);
    assert.equal(response.status, settings.UPSTREAM_URL ? 500 : 503);
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
    assert.equal(request.url, "https://relay.example.org/family-vpn/endpoints?test=1");
    assert.equal(request.method, "POST");
    assert.equal(request.headers.get("Host"), "relay.example.org");
    assert.equal(await request.text(), payload);
    for (const [key, value] of Object.entries(headers)) assert.equal(request.headers.get(key), value);
    assert.equal(request.headers.get("X-Relay-Proxy-Token"), env.RELAY_PROXY_TOKEN);
    assert.equal(options.redirect, "manual");
    return upstreamResponse;
  });
  try {
    const request = new Request("https://push.family-vpn.workers.dev/endpoints?test=1", { method: "POST", headers, body: payload });
    const response = await worker.fetch(request, env);
    assert.equal(await response.text(), "rate limit");
    assert.equal(response.headers.get("X-Relay-Proxy-Token"), null);
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


test("optional Worker secret is omitted and caller header stripped; arbitrary routes blocked", async () => {
  const stub = mock.method(globalThis, "fetch", (request) => {
    assert.equal(request.headers.get("X-Relay-Proxy-Token"), null);
    return new Response("ok");
  });
  try {
    const response = await worker.fetch(new Request("https://push.family-vpn.workers.dev/push", { method: "POST", headers: { "X-Relay-Proxy-Token": "caller-value" } }), { UPSTREAM_URL: env.UPSTREAM_URL });
    assert.equal(response.status, 200);
    assert.equal((await worker.fetch(new Request("https://push.family-vpn.workers.dev/registrations", { method: "POST" }), env)).status, 404);
    assert.equal(stub.mock.callCount(), 1);
  } finally { stub.mock.restore(); }
});

test("caller cannot choose the Worker credential and it is removed from responses", async () => {
  const stub = mock.method(globalThis, "fetch", (request) => {
    assert.equal(request.headers.get("X-Relay-Proxy-Token"), env.RELAY_PROXY_TOKEN);
    return new Response("ok", { headers: { "X-Relay-Proxy-Token": env.RELAY_PROXY_TOKEN } });
  });
  try {
    const response = await worker.fetch(new Request("https://push.family-vpn.workers.dev/rotate", { method: "POST", headers: { "X-Relay-Proxy-Token": "attacker-value" } }), env);
    assert.equal(response.headers.get("X-Relay-Proxy-Token"), null);
    assert.equal(await response.text(), "ok");
  } finally { stub.mock.restore(); }
});
