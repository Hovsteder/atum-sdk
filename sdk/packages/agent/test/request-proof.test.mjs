import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';

import { AgentError, createAgentKey, createRequestProofClient } from '../src/index.mjs';
import { canonical } from '../src/strict.mjs';

const vector = JSON.parse(readFileSync(new URL('../../../protocol/owner-consent/owner-consent-v1.json', import.meta.url)));
const privateJwk = vector.test_private_jwk;
const publicJwk = { kty: privateJwk.kty, crv: privateJwk.crv, x: privateJwk.x, y: privateJwk.y };
const privateKey = createPrivateKey({ key: privateJwk, format: 'jwk' });
const publicKey = createPublicKey({ key: publicJwk, format: 'jwk' });
const NOW = 1_700_000_000_123;
const REQUEST_ID = '123e4567-e89b-42d3-a456-426614174000';
const CHALLENGE_ID = '223e4567-e89b-42d3-a456-426614174000';
const NONCE = Buffer.alloc(32, 0x35).toString('base64url');
const HANDLE = Buffer.alloc(32, 0x1c).toString('base64url');

function openssl(dir, ...args) { execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' }); }
function certificates() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'atum-agent-request-'));
  writeFileSync(path.join(dir, 'server.ext'), 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n');
  openssl(dir, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-subj', '/CN=atum-agent-test-ca');
  openssl(dir, 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'server.key', '-out', 'server.csr', '-subj', '/CN=localhost');
  openssl(dir, 'x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'server.pem', '-days', '1', '-extfile', 'server.ext');
  return { dir, ca: readFileSync(path.join(dir, 'ca.pem'), 'utf8'), cert: readFileSync(path.join(dir, 'server.pem')), key: readFileSync(path.join(dir, 'server.key')) };
}
async function host(handler) {
  const certs = certificates();
  const server = https.createServer({ cert: certs.cert, key: certs.key }, handler);
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const origin = `https://localhost:${server.address().port}`;
  return { certs, origin, close: async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); rmSync(certs.dir, { recursive: true, force: true }); } };
}
function json(res, status, value) {
  const body = Buffer.from(JSON.stringify(value));
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': String(body.length), 'cache-control': 'no-store' });
  res.end(body);
}
async function requestBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks));
}
function hash(domain, value) { return `sha256:${createHash('sha256').update(domain, 'ascii').update(canonical(value), 'utf8').digest('hex')}`; }
function profile(origin) {
  const registration = structuredClone(vector.registry.registration);
  registration.issuer = origin;
  return { registration, client: structuredClone(vector.registry.clients[0]) };
}
function input(flow = 'authorization_code') {
  const original = flow === 'authorization_code' ? vector.input : vector.device.input;
  const detail = original.authorization_details[0];
  return flow === 'authorization_code'
    ? { flow, permissions: structuredClone(detail.permissions), grant_limit: detail.grant_limit, grant_expires_at_ms: NOW + 299_877,
      redirect_uri: original.code.redirect_uri, code_challenge: original.code.code_challenge, state: original.code.state }
    : { flow, permissions: structuredClone(detail.permissions), grant_limit: detail.grant_limit, grant_expires_at_ms: NOW + 299_877 };
}
function expectedOptionsBody(intent, registration, client) {
  const detail = { type: 'atum', permissions: [...intent.permissions].sort((a, b) => a.action < b.action ? -1 : a.action > b.action ? 1 : 0), grant_limit: intent.grant_limit, grant_expires_at_ms: intent.grant_expires_at_ms };
  return { flow: intent.flow, client_id: client.client_id, resource: registration.audience, authorization_details: [detail],
    code: intent.flow === 'authorization_code' ? { redirect_uri: intent.redirect_uri, code_challenge: intent.code_challenge, code_challenge_method: 'S256', state: intent.state } : null,
    agent_jwk: publicJwk };
}
function normalized(optionsBody, registration) {
  const detail = optionsBody.authorization_details[0];
  const normalizedRegistration = { ...registration, account_required_actions: [...registration.account_required_actions].sort() };
  return { profile: 'atum-oauth-request-v1', request_id: REQUEST_ID, created_at_ms: NOW, expires_at_ms: Math.floor(Math.min(NOW + 300_000, detail.grant_expires_at_ms) / 1000) * 1000,
    issuer: registration.issuer, environment: 'sandbox', flow: optionsBody.flow, client_id: optionsBody.client_id, registration: normalizedRegistration,
    resource: registration.audience, scope: 'atum:invoke', permissions: detail.permissions, grant_limit: detail.grant_limit,
    grant_expires_at_ms: detail.grant_expires_at_ms, code: optionsBody.code };
}
function preparedResponse(optionsBody, registration) {
  const request = normalized(optionsBody, registration);
  return { request, request_hash: hash('atum.oauth.request.v1\n', request), challenge_id: CHALLENGE_ID,
    nonce: NONCE, iat: Math.floor(request.created_at_ms / 1000), exp: request.expires_at_ms / 1000 };
}
function verifyResponse(prepared, state = 'verified') {
  return { atum_request: HANDLE, request_id: prepared.request.request_id, request_hash: prepared.request_hash,
    agent_key_thumbprint: vector.expected.agent_key_thumbprint, state, expires_at_ms: prepared.request.expires_at_ms };
}
function endpoints(origin) {
  return { options_url: `${origin}/atum/request/options`, verify_url: `${origin}/atum/request/verify`, par_url: `${origin}/request`,
    authorization_url: `${origin}/auth`, device_authorization_url: `${origin}/device/auth`, token_url: `${origin}/token` };
}
async function agentKey(sign = async data => nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' }), timeoutMs = 500) {
  return createAgentKey({ publicJwk, sign, timeoutMs });
}
function config(h, key, extra = {}) {
  const { registration, client } = profile(h.origin);
  return { registration, client, endpoints: endpoints(h.origin), tls: { ca: h.certs.ca }, key,
    clock: () => ({ healthy: true, now_ms: NOW, uncertainty_ms: 0 }), timeoutMs: 500, maxConcurrent: 2, ...extra };
}
function expectCode(code) { return error => error instanceof AgentError && error.code === code; }

test('real TLS request preparation compares options before signing and returns only frozen correlations', async t => {
  const seen = [];
  const h = await host(async (req, res) => {
    assert.equal(req.method, 'POST');
    assert.equal(req.headers.authorization, undefined); assert.equal(req.headers.cookie, undefined);
    const body = await requestBody(req); seen.push([req.url, body]);
    const { registration, client } = profile(h.origin);
    if (req.url === '/atum/request/options') return json(res, 200, preparedResponse(expectedOptionsBody(input(body.flow), registration, client), registration));
    const prepared = preparedResponse(seen.at(-2)[1], registration);
    assert.deepEqual(Object.keys(body).sort(), ['challenge_id', 'proof']);
    assert.equal(body.challenge_id, CHALLENGE_ID);
    const [encodedHeader, encodedClaims, encodedSignature] = body.proof.split('.');
    assert.deepEqual(JSON.parse(Buffer.from(encodedHeader, 'base64url')), { alg: 'ES256', jwk: publicJwk, typ: 'atum-oauth-request+jwt' });
    assert.deepEqual(JSON.parse(Buffer.from(encodedClaims, 'base64url')), { aud: registration.issuer, exp: prepared.exp, iat: prepared.iat,
      iss: client.client_id, jti: CHALLENGE_ID, nonce: prepared.nonce, purpose: 'prepare_owner_consent', request_hash: prepared.request_hash, request_id: REQUEST_ID });
    assert.equal(nodeVerify('sha256', Buffer.from(`${encodedHeader}.${encodedClaims}`), { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(encodedSignature, 'base64url')), true);
    return json(res, 200, verifyResponse(prepared));
  });
  t.after(h.close);
  const key = await agentKey(); const configured = config(h, key); const client = createRequestProofClient(configured);
  configured.registration.audience = 'https://mutated.example';
  configured.client.client_id = 'mutated-client';
  configured.endpoints.options_url = 'https://mutated.example/options';
  for (const flow of ['authorization_code', 'device_code']) {
    const value = input(flow); const expected = structuredClone(value); const pending = client.prepare(value);
    value.permissions[0].action = 'changed'; value.grant_limit = 999;
    const result = await pending;
    assert.equal(result.request.flow, flow); assert.equal(result.atum_request, HANDLE); assert.equal(result.request_hash, hash('atum.oauth.request.v1\n', result.request));
    assert.equal(result.expires_at_ms, result.request.expires_at_ms); assert.equal(Object.isFrozen(result), true); assert.equal(Object.isFrozen(result.request.registration), true);
    assert.deepEqual(seen.at(-2)[1], expectedOptionsBody(expected, profile(h.origin).registration, profile(h.origin).client));
  }
  assert.equal(seen.length, 4);
  await client.close();
});

test('options substitutions fail before the key or verify route is used', async t => {
  let mutation = value => value; let verifyCalls = 0; let signCalls = 0;
  const h = await host(async (req, res) => {
    const body = await requestBody(req); const { registration } = profile(h.origin);
    if (req.url === '/atum/request/verify') { verifyCalls += 1; return json(res, 500, {}); }
    return json(res, 200, mutation(preparedResponse(body, registration)));
  });
  t.after(h.close);
  const key = await agentKey(async data => { signCalls += 1; return nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' }); });
  const client = createRequestProofClient(config(h, key));
  const requestMutation = change => value => {
    const request = change(value.request);
    return { ...value, request, request_hash: hash('atum.oauth.request.v1\n', request) };
  };
  const mutations = [
    requestMutation(request => ({ ...request, resource: 'https://foreign.example' })),
    requestMutation(request => ({ ...request, permissions: [{ action: 'prices.read' }] })),
    requestMutation(request => ({ ...request, request_id: 'not-a-uuid' })),
    requestMutation(request => ({ ...request, request_id: [REQUEST_ID] })),
    requestMutation(request => ({ ...request, expires_at_ms: request.expires_at_ms + 1000 })),
    value => ({ ...value, request_hash: `sha256:${'0'.repeat(64)}` }),
    value => ({ ...value, challenge_id: [CHALLENGE_ID] }),
    value => ({ ...value, nonce: 'short' }),
  ];
  for (const change of mutations) {
    mutation = change;
    await assert.rejects(client.prepare(input()), expectCode('temporarily_unavailable'));
  }
  assert.equal(signCalls, 0); assert.equal(verifyCalls, 0);
  await client.close();
});

test('server-created time enforces the registered grant lifetime cap', async t => {
  let signCalls = 0; let verifyCalls = 0;
  const h = await host(async (req, res) => {
    const body = await requestBody(req); const { registration } = profile(h.origin);
    if (req.url.endsWith('/verify')) { verifyCalls += 1; return json(res, 500, {}); }
    const value = preparedResponse(body, registration);
    const request = { ...value.request, created_at_ms: NOW - 1_000 };
    request.expires_at_ms = Math.floor(Math.min(request.created_at_ms + 300_000, request.grant_expires_at_ms) / 1000) * 1000;
    return json(res, 200, { ...value, request, request_hash: hash('atum.oauth.request.v1\n', request),
      iat: Math.floor(request.created_at_ms / 1000), exp: request.expires_at_ms / 1000 });
  });
  t.after(h.close);
  const key = await agentKey(async data => { signCalls += 1; return nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' }); });
  const client = createRequestProofClient(config(h, key, { clock: () => ({ healthy: true, now_ms: NOW, uncertainty_ms: 1_000 }) }));
  const value = input(); value.grant_expires_at_ms = NOW + profile(h.origin).client.max_grant_lifetime_ms;
  await assert.rejects(client.prepare(value), expectCode('temporarily_unavailable'));
  assert.equal(signCalls, 0); assert.equal(verifyCalls, 0);
  await client.close();
});

test('verify response requires exact captured correlations and verified state', async t => {
  let alter = value => value;
  const h = await host(async (req, res) => {
    const body = await requestBody(req); const { registration } = profile(h.origin);
    const prepared = req.url.endsWith('/options') ? preparedResponse(body, registration) : h.prepared;
    if (req.url.endsWith('/options')) { h.prepared = prepared; return json(res, 200, prepared); }
    return json(res, 200, alter(verifyResponse(prepared)));
  });
  t.after(h.close);
  const client = createRequestProofClient(config(h, await agentKey()));
  for (const change of [
    value => ({ ...value, request_id: '323e4567-e89b-42d3-a456-426614174000' }),
    value => ({ ...value, request_hash: `sha256:${'0'.repeat(64)}` }),
    value => ({ ...value, agent_key_thumbprint: 'A'.repeat(43) }),
    value => ({ ...value, expires_at_ms: value.expires_at_ms - 1000 }),
    value => ({ ...value, state: 'pending' }),
  ]) {
    alter = change;
    await assert.rejects(client.prepare(input()), expectCode('temporarily_unavailable'));
  }
  alter = value => ({ ...value, state: 'expired' });
  await assert.rejects(client.prepare(input()), expectCode('expired_token'));
  await client.close();
});

test('a stalled or late signer exhausts the operation deadline and never starts verify HTTP', async t => {
  let verifyCalls = 0; let release;
  const h = await host(async (req, res) => {
    const body = await requestBody(req); const { registration } = profile(h.origin);
    if (req.url.endsWith('/verify')) { verifyCalls += 1; return json(res, 500, {}); }
    return json(res, 200, preparedResponse(body, registration));
  });
  t.after(h.close);
  const neverKey = await agentKey(async () => new Promise(() => {}), 100);
  const neverClient = createRequestProofClient(config(h, neverKey, { timeoutMs: 25 }));
  const neverStarted = performance.now();
  await assert.rejects(neverClient.prepare(input()), expectCode('temporarily_unavailable'));
  assert.ok(performance.now() - neverStarted < 100); assert.equal(verifyCalls, 0);
  await neverClient.close();

  const key = await agentKey(async data => new Promise(resolve => { release = () => resolve(nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' })); }), 100);
  const client = createRequestProofClient(config(h, key, { timeoutMs: 25 }));
  const started = performance.now();
  await assert.rejects(client.prepare(input()), expectCode('temporarily_unavailable'));
  assert.ok(performance.now() - started < 100); assert.equal(verifyCalls, 0);
  release(); await delay(80); assert.equal(verifyCalls, 0);
  await client.close();
});

test('whole-operation capacity and close include paused signers and fence late HTTP', async t => {
  let optionsCalls = 0; let verifyCalls = 0; const releases = [];
  const h = await host(async (req, res) => {
    const body = await requestBody(req); const { registration } = profile(h.origin);
    if (req.url.endsWith('/verify')) { verifyCalls += 1; return json(res, 500, {}); }
    optionsCalls += 1; return json(res, 200, preparedResponse(body, registration));
  });
  t.after(h.close);
  const key = await agentKey(async data => new Promise(resolve => {
    releases.push(() => resolve(nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' })));
  }), 500);
  const client = createRequestProofClient(config(h, key, { timeoutMs: 500, maxConcurrent: 1 }));
  const first = client.prepare(input());
  first.catch(() => {});
  while (releases.length === 0) await delay(1);
  const second = client.prepare(input('device_code'));
  await assert.rejects(second, expectCode('temporarily_unavailable'));
  assert.equal(optionsCalls, 1); assert.equal(releases.length, 1);
  const closed = client.close();
  await assert.rejects(first, expectCode('temporarily_unavailable'));
  await closed;
  releases[0](); await delay(30);
  assert.equal(verifyCalls, 0);
  await assert.rejects(client.prepare(input()), expectCode('temporarily_unavailable'));
});

test('invalid local intent and accessor input fail before network without invoking accessors', async t => {
  let calls = 0; let getters = 0;
  const h = await host((_req, res) => { calls += 1; json(res, 500, {}); }); t.after(h.close);
  const validKey = await agentKey();
  assert.throws(() => createRequestProofClient(config(h, Object.freeze({ publicJwk, thumbprint: vector.expected.agent_key_thumbprint, sign: validKey.sign }))), TypeError);
  const client = createRequestProofClient(config(h, validKey));
  const accessor = input();
  Object.defineProperty(accessor, 'permissions', { enumerable: true, get() { getters += 1; return []; } });
  for (const value of [accessor, { ...input(), unknown: true }, { ...input(), grant_limit: -0 }, { ...input(), permissions: [] }]) {
    let pending;
    assert.doesNotThrow(() => { pending = client.prepare(value); });
    await assert.rejects(pending, expectCode('invalid_request'));
  }
  assert.equal(getters, 0); assert.equal(calls, 0);
  await client.close();
});
