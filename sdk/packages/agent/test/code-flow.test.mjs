import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, randomBytes, sign as nodeSign, verify as nodeVerify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { AgentError, createAgentClient, createAgentKey } from '../src/index.mjs';
import { canonical } from '../src/strict.mjs';

const vector = JSON.parse(readFileSync(new URL('../../../protocol/owner-consent/owner-consent-v1.json', import.meta.url)));
const privateJwk = vector.test_private_jwk;
const publicJwk = { kty: privateJwk.kty, crv: privateJwk.crv, x: privateJwk.x, y: privateJwk.y };
const privateKey = createPrivateKey({ key: privateJwk, format: 'jwk' });
const publicKey = createPublicKey({ key: publicJwk, format: 'jwk' });
const REQUEST_ID = '123e4567-e89b-42d3-a456-426614174000';
const CHALLENGE_ID = '223e4567-e89b-42d3-a456-426614174000';
const NONCE = Buffer.alloc(32, 0x35).toString('base64url');
const HANDLE = Buffer.alloc(32, 0x1c).toString('base64url');
const DPOP_NONCE = Buffer.alloc(32, 0x41).toString('base64url');
const CODE = 'C'.repeat(43);
const FIRST_REFRESH = 'R'.repeat(43);
const SECOND_REFRESH = 'S'.repeat(43);
const ACCESS = `${Buffer.from('{"alg":"RS256"}').toString('base64url')}.${Buffer.from('{"sub":"owner"}').toString('base64url')}.${'A'.repeat(342)}`;

function openssl(dir, ...args) { execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' }); }
function certificates() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'atum-agent-code-flow-'));
  writeFileSync(path.join(dir, 'server.ext'), 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n');
  openssl(dir, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-subj', '/CN=atum-agent-code-flow-ca');
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
function json(res, status, value, extra = {}) {
  const body = Buffer.from(JSON.stringify(value));
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': String(body.length), 'cache-control': 'no-store', ...extra });
  res.end(body);
}
async function body(req) { const chunks = []; for await (const chunk of req) chunks.push(chunk); return Buffer.concat(chunks); }
function hash(domain, value) { return `sha256:${createHash('sha256').update(domain, 'ascii').update(canonical(value), 'utf8').digest('hex')}`; }
function profile(origin) { const registration = structuredClone(vector.registry.registration); registration.issuer = origin; return { registration, client: structuredClone(vector.registry.clients[0]) }; }
function endpoints(origin) { return { options_url: `${origin}/atum/request/options`, verify_url: `${origin}/atum/request/verify`, par_url: `${origin}/request`, authorization_url: `${origin}/auth`, device_authorization_url: `${origin}/device/auth`, token_url: `${origin}/token` }; }
function requestInput() { const detail = vector.input.authorization_details[0]; return { permissions: structuredClone(detail.permissions), grant_limit: detail.grant_limit, grant_expires_at_ms: now + 299_877, redirect_uri: vector.input.code.redirect_uri }; }
function expectedOptionsBody(intent, registration, client, code) {
  const detail = { type: 'atum', permissions: [...intent.permissions].sort((a, b) => a.action < b.action ? -1 : a.action > b.action ? 1 : 0), grant_limit: intent.grant_limit, grant_expires_at_ms: intent.grant_expires_at_ms };
  return { flow: 'authorization_code', client_id: client.client_id, resource: registration.audience, authorization_details: [detail],
    code: { redirect_uri: intent.redirect_uri, code_challenge: code.code_challenge, code_challenge_method: 'S256', state: code.state }, agent_jwk: publicJwk };
}
function normalized(options, registration) {
  const detail = options.authorization_details[0]; const normalizedRegistration = { ...registration, account_required_actions: [...registration.account_required_actions].sort() };
  return { profile: 'atum-oauth-request-v1', request_id: REQUEST_ID, created_at_ms: now, expires_at_ms: Math.floor(Math.min(now + 300_000, detail.grant_expires_at_ms) / 1000) * 1000,
    issuer: registration.issuer, environment: 'sandbox', flow: options.flow, client_id: options.client_id, registration: normalizedRegistration,
    resource: registration.audience, scope: 'atum:invoke', permissions: detail.permissions, grant_limit: detail.grant_limit,
    grant_expires_at_ms: detail.grant_expires_at_ms, code: options.code };
}
function preparedResponse(options, registration) { const request = normalized(options, registration); return { request, request_hash: hash('atum.oauth.request.v1\n', request), challenge_id: CHALLENGE_ID, nonce: NONCE, iat: Math.floor(request.created_at_ms / 1000), exp: request.expires_at_ms / 1000 }; }
function verifyResponse(prepared) { return { atum_request: HANDLE, request_id: prepared.request.request_id, request_hash: prepared.request_hash, agent_key_thumbprint: vector.expected.agent_key_thumbprint, state: 'verified', expires_at_ms: prepared.request.expires_at_ms }; }
function details(request) { return [{ type: 'atum', permissions: request.permissions, grant_limit: request.grant_limit, grant_expires_at_ms: request.grant_expires_at_ms }]; }
function token(request, refresh) { return { access_token: ACCESS, expires_in: 60, refresh_token: refresh, scope: 'atum:invoke', token_type: 'DPoP', authorization_details: details(request) }; }
function decodeProof(value) {
  const [header, claims, signature] = value.split('.');
  const decodedHeader = JSON.parse(Buffer.from(header, 'base64url')); const decodedClaims = JSON.parse(Buffer.from(claims, 'base64url'));
  assert.equal(nodeVerify('sha256', Buffer.from(`${header}.${claims}`), { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64url')), true);
  return { header: decodedHeader, claims: decodedClaims };
}
async function key() { return createAgentKey({ publicJwk, sign: async data => nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' }) }); }
let now = 1_700_000_000_123;
function config(h, agentKey, extra = {}) { const { registration, client } = profile(h.origin); return { registration, client, endpoints: endpoints(h.origin), tls: { ca: h.certs.ca }, key: agentKey, clock: () => ({ healthy: true, now_ms: now, uncertainty_ms: 0 }), timeoutMs: 500, maxConcurrent: 2, ...extra }; }
function expectCode(code) { return error => error instanceof AgentError && error.code === code; }

test('real TLS code flow prepares, signs PAR, validates PKCE callback and exchanges the one nonce continuation', async t => {
  now = 1_700_000_000_123;
  let prepared; let par; let tokenCalls = 0; let requestSeen;
  const h = await host(async (req, res) => {
    const raw = await body(req);
    const { registration, client } = profile(h.origin);
    if (req.url === '/atum/request/options') { requestSeen = JSON.parse(raw); prepared = preparedResponse(requestSeen, registration); return json(res, 200, prepared); }
    if (req.url === '/atum/request/verify') return json(res, 200, verifyResponse(prepared));
    if (req.url === '/request') {
      par = Object.fromEntries(new URLSearchParams(raw.toString('utf8'))); const proof = decodeProof(req.headers.dpop);
      assert.deepEqual(Object.keys(par).sort(), ['atum_request', 'authorization_details', 'client_id', 'code_challenge', 'code_challenge_method', 'dpop_jkt', 'redirect_uri', 'resource', 'response_type', 'scope', 'state']);
      assert.equal(par.atum_request, HANDLE); assert.equal(par.client_id, client.client_id); assert.equal(par.resource, registration.audience); assert.equal(par.scope, 'atum:invoke');
      assert.equal(par.code_challenge_method, 'S256'); assert.equal(par.dpop_jkt, vector.expected.agent_key_thumbprint);
      assert.deepEqual(JSON.parse(par.authorization_details), details(prepared.request));
      assert.deepEqual(proof.header, { alg: 'ES256', jwk: publicJwk, typ: 'dpop+jwt' });
      assert.deepEqual(Object.keys(proof.claims).sort(), ['htm', 'htu', 'iat', 'jti']); assert.equal(proof.claims.htm, 'POST'); assert.equal(proof.claims.htu, `${h.origin}/request`);
      return json(res, 201, { request_uri: `urn:ietf:params:oauth:request_uri:${'P'.repeat(43)}`, expires_in: 60 });
    }
    assert.equal(req.url, '/token'); tokenCalls += 1;
    const form = Object.fromEntries(new URLSearchParams(raw.toString('utf8'))); const proof = decodeProof(req.headers.dpop);
    assert.equal(proof.claims.htm, 'POST'); assert.equal(proof.claims.htu, `${h.origin}/token`);
    if (tokenCalls === 1) {
      assert.equal(form.grant_type, 'authorization_code'); assert.equal(form.code, CODE); assert.equal(form.redirect_uri, vector.input.code.redirect_uri);
      assert.equal(createHash('sha256').update(form.code_verifier, 'ascii').digest('base64url'), par.code_challenge);
      assert.equal(proof.claims.nonce, undefined); return json(res, 400, { error: 'use_dpop_nonce' }, { 'dpop-nonce': DPOP_NONCE });
    }
    if (tokenCalls === 2) { assert.equal(proof.claims.nonce, DPOP_NONCE); return json(res, 200, token(prepared.request, FIRST_REFRESH)); }
    assert.equal(form.grant_type, 'refresh_token'); assert.equal(form.refresh_token, FIRST_REFRESH);
    if (tokenCalls === 3) { assert.equal(proof.claims.nonce, undefined); return json(res, 400, { error: 'use_dpop_nonce' }, { 'dpop-nonce': DPOP_NONCE }); }
    assert.equal(proof.claims.nonce, DPOP_NONCE); return json(res, 200, token(prepared.request, SECOND_REFRESH));
  });
  t.after(h.close);
  const client = await createAgentClient(config(h, await key()));
  const started = await client.beginAuthorizationCode(requestInput());
  assert.equal(started.request_id, REQUEST_ID); assert.equal(started.expires_at_ms, prepared.request.expires_at_ms); assert.equal(Object.isFrozen(started), true);
  const authorization = new URL(started.authorization_url);
  assert.equal(authorization.origin + authorization.pathname, h.origin + '/auth');
  assert.deepEqual([...authorization.searchParams].sort(), [['client_id', profile(h.origin).client.client_id], ['request_uri', `urn:ietf:params:oauth:request_uri:${'P'.repeat(43)}`]]);
  assert.equal(started.authorization_url.includes(par.state), false);
  const tokens = await started.completeCallback(`${vector.input.code.redirect_uri}?code=${CODE}&state=${encodeURIComponent(par.state)}&iss=${encodeURIComponent(h.origin)}`);
  assert.equal(tokens.refresh_token, FIRST_REFRESH); assert.equal(tokenCalls, 2);
  const refreshed = await client.refresh({ refresh_token: FIRST_REFRESH, authorization_details: tokens.authorization_details });
  assert.equal(refreshed.refresh_token, SECOND_REFRESH); assert.equal(tokenCalls, 4);
  assert.equal(requestSeen.code.code_challenge, par.code_challenge);
  await client.close();
});

test('native retrieval expiry does not shorten the original callback cap, while callback shape and completion remain terminal', async t => {
  now = 1_700_000_000_123;
  let prepared; let state; let tokenCalls = 0;
  const h = await host(async (req, res) => {
    const raw = await body(req); const { registration } = profile(h.origin);
    if (req.url === '/atum/request/options') { prepared = preparedResponse(JSON.parse(raw), registration); return json(res, 200, prepared); }
    if (req.url === '/atum/request/verify') return json(res, 200, verifyResponse(prepared));
    if (req.url === '/request') { state = new URLSearchParams(raw.toString('utf8')).get('state'); return json(res, 201, { request_uri: `urn:ietf:params:oauth:request_uri:${'P'.repeat(43)}`, expires_in: 1 }); }
    tokenCalls += 1;
    if (tokenCalls === 1) return json(res, 400, { error: 'use_dpop_nonce' }, { 'dpop-nonce': DPOP_NONCE });
    return json(res, 200, token(prepared.request, FIRST_REFRESH));
  });
  t.after(h.close);
  const client = await createAgentClient(config(h, await key()));
  const flow = await client.beginAuthorizationCode(requestInput());
  now += 2_000;
  const tokens = await flow.completeCallback(`${vector.input.code.redirect_uri}?code=${CODE}&state=${state}&iss=${encodeURIComponent(h.origin)}`);
  assert.equal(tokens.refresh_token, FIRST_REFRESH); assert.equal(tokenCalls, 2);
  await assert.rejects(flow.completeCallback(`${vector.input.code.redirect_uri}?code=${CODE}&state=${state}&iss=${encodeURIComponent(h.origin)}`), expectCode('invalid_request'));

  const invalid = await client.beginAuthorizationCode(requestInput());
  await assert.rejects(invalid.completeCallback(`${vector.input.code.redirect_uri}?code=${CODE}&code=${CODE}&state=${state}&iss=${encodeURIComponent(h.origin)}`), expectCode('invalid_request'));
  await assert.rejects(invalid.completeCallback(`${vector.input.code.redirect_uri}?code=${CODE}&state=${state}&iss=${encodeURIComponent(h.origin)}`), expectCode('invalid_request'));
  for (const callback of [
    current => `https://wrong.example/callback?code=${CODE}&state=${current}&iss=${encodeURIComponent(h.origin)}`,
    current => `${vector.input.code.redirect_uri}?code=${CODE}&state=${current}&iss=${encodeURIComponent(h.origin)}#fragment`,
    current => `${vector.input.code.redirect_uri}?code=${CODE}&state=${current}&extra=x&iss=${encodeURIComponent(h.origin)}`,
    current => `${vector.input.code.redirect_uri}?code=${CODE}&state=${current}`,
    current => `${vector.input.code.redirect_uri}?code=${CODE}&state=${current}&iss=${encodeURIComponent(h.origin)}#`,
    current => `${vector.input.code.redirect_uri}?code=${CODE}&state=${current}&iss=${encodeURIComponent(h.origin)}&padding=${'A'.repeat(4096)}`,
  ]) {
    const altered = await client.beginAuthorizationCode(requestInput()); const current = state;
    await assert.rejects(altered.completeCallback(callback(current)), expectCode('invalid_request'));
  }
  const cancelled = await client.beginAuthorizationCode(requestInput());
  await assert.rejects(cancelled.completeCallback(`${vector.input.code.redirect_uri}?error=access_denied&error_description=owner+declined&state=${state}&iss=${encodeURIComponent(h.origin)}`), expectCode('access_denied'));
  assert.equal(tokenCalls, 2);
  await client.close();
});

test('expired callbacks, active-close and malformed public input do not start token I/O', async t => {
  now = 1_700_000_000_123;
  let prepared; let state; let tokens = 0;
  const h = await host(async (req, res) => {
    const raw = await body(req); const { registration } = profile(h.origin);
    if (req.url === '/atum/request/options') { prepared = preparedResponse(JSON.parse(raw), registration); return json(res, 200, prepared); }
    if (req.url === '/atum/request/verify') return json(res, 200, verifyResponse(prepared));
    if (req.url === '/request') { state = new URLSearchParams(raw.toString('utf8')).get('state'); return json(res, 201, { request_uri: `urn:ietf:params:oauth:request_uri:${'P'.repeat(43)}`, expires_in: 60 }); }
    tokens += 1; return json(res, 200, token(prepared.request, FIRST_REFRESH));
  });
  t.after(h.close);
  const client = await createAgentClient(config(h, await key()));
  await assert.rejects(client.beginAuthorizationCode({ ...requestInput(), extra: true }), expectCode('invalid_request'));
  const flow = await client.beginAuthorizationCode(requestInput());
  now = prepared.request.expires_at_ms;
  await assert.rejects(flow.completeCallback(`${vector.input.code.redirect_uri}?code=${CODE}&state=${state}&iss=${encodeURIComponent(h.origin)}`), expectCode('expired_token'));
  assert.equal(tokens, 0);
  await client.close();
  await assert.rejects(client.beginAuthorizationCode(requestInput()), expectCode('temporarily_unavailable'));
});

test('concurrent callback completion is one-shot and close aborts a signer before PAR', async t => {
  now = 1_700_000_000_123;
  let prepared; let state; let tokenCalls = 0; let verifyCalls = 0; let parCalls = 0; let release;
  const h = await host(async (req, res) => {
    const raw = await body(req); const { registration } = profile(h.origin);
    if (req.url === '/atum/request/options') { prepared = preparedResponse(JSON.parse(raw), registration); return json(res, 200, prepared); }
    if (req.url === '/atum/request/verify') { verifyCalls += 1; return json(res, 200, verifyResponse(prepared)); }
    if (req.url === '/request') { parCalls += 1; state = new URLSearchParams(raw.toString('utf8')).get('state'); return json(res, 201, { request_uri: `urn:ietf:params:oauth:request_uri:${'P'.repeat(43)}`, expires_in: 60 }); }
    tokenCalls += 1;
    if (tokenCalls % 2 === 1) return json(res, 400, { error: 'use_dpop_nonce' }, { 'dpop-nonce': DPOP_NONCE });
    return json(res, 200, token(prepared.request, FIRST_REFRESH));
  });
  t.after(h.close);
  const client = await createAgentClient(config(h, await key()));
  const flow = await client.beginAuthorizationCode(requestInput());
  const callback = `${vector.input.code.redirect_uri}?code=${CODE}&state=${state}&iss=${encodeURIComponent(h.origin)}`;
  const first = flow.completeCallback(callback);
  await assert.rejects(flow.completeCallback(callback), expectCode('invalid_request'));
  await first; assert.equal(tokenCalls, 2);
  await client.close();

  const stalledKey = await createAgentKey({ publicJwk, timeoutMs: 500, sign: async data => new Promise(resolve => { release = () => resolve(nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' })); }) });
  const bounded = await createAgentClient(config(h, stalledKey));
  const pending = bounded.beginAuthorizationCode(requestInput());
  while (!release) await new Promise(resolve => setTimeout(resolve, 1));
  await bounded.close();
  await assert.rejects(pending, expectCode('temporarily_unavailable'));
  release();
  assert.equal(verifyCalls, 1); assert.equal(parCalls, 1);
});

test('the original prepared-request cap fences a nonce continuation inside the token child', async t => {
  now = 1_700_000_000_123;
  let prepared; let state; let tokenCalls = 0;
  const h = await host(async (req, res) => {
    const raw = await body(req); const { registration } = profile(h.origin);
    if (req.url === '/atum/request/options') { prepared = preparedResponse(JSON.parse(raw), registration); return json(res, 200, prepared); }
    if (req.url === '/atum/request/verify') return json(res, 200, verifyResponse(prepared));
    if (req.url === '/request') { state = new URLSearchParams(raw.toString('utf8')).get('state'); return json(res, 201, { request_uri: `urn:ietf:params:oauth:request_uri:${'P'.repeat(43)}`, expires_in: 60 }); }
    tokenCalls += 1;
    if (tokenCalls === 1) { now = prepared.request.expires_at_ms; return json(res, 400, { error: 'use_dpop_nonce' }, { 'dpop-nonce': DPOP_NONCE }); }
    return json(res, 200, token(prepared.request, FIRST_REFRESH));
  });
  t.after(h.close);
  const configured = config(h, await key()); configured.client.max_grant_lifetime_ms = 3_600_000;
  const client = await createAgentClient(configured);
  const flow = await client.beginAuthorizationCode({ ...requestInput(), grant_expires_at_ms: now + 600_000 });
  await assert.rejects(flow.completeCallback(`${vector.input.code.redirect_uri}?code=${CODE}&state=${state}&iss=${encodeURIComponent(h.origin)}`), expectCode('expired_token'));
  assert.equal(tokenCalls, 1);
  await client.close();
});

test('a child proof inherits the parent measured-clock history before it can send options', async t => {
  now = 1_700_000_000_123;
  let optionsCalls = 0; let clockCalls = 0;
  const h = await host((_req, res) => { optionsCalls += 1; json(res, 500, {}); }); t.after(h.close);
  const configured = config(h, await key(), { clock: () => {
    clockCalls += 1;
    return { healthy: true, now_ms: clockCalls === 1 ? now : now - 1, uncertainty_ms: 0 };
  } });
  const client = await createAgentClient(configured);
  await assert.rejects(client.beginAuthorizationCode(requestInput()), expectCode('temporarily_unavailable'));
  assert.equal(optionsCalls, 0);
  await client.close();
});

test('the prepared-request cap stops PAR DPoP signing before a second key operation', async t => {
  now = 1_700_000_000_123;
  let prepared; let clockReads = 0; let signs = 0; let parCalls = 0;
  const h = await host(async (req, res) => {
    const raw = await body(req); const { registration } = profile(h.origin);
    if (req.url === '/atum/request/options') { prepared = preparedResponse(JSON.parse(raw), registration); return json(res, 200, prepared); }
    if (req.url === '/atum/request/verify') return json(res, 200, verifyResponse(prepared));
    if (req.url === '/request') { parCalls += 1; return json(res, 201, { request_uri: `urn:ietf:params:oauth:request_uri:${'P'.repeat(43)}`, expires_in: 60 }); }
    assert.fail(`unexpected token request ${req.url}`);
  });
  t.after(h.close);
  const trackedKey = await createAgentKey({ publicJwk, sign: async data => {
    signs += 1;
    return nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  } });
  const client = await createAgentClient(config(h, trackedKey, { clock: () => {
    clockReads += 1;
    if (clockReads === 7) now = prepared.request.expires_at_ms;
    return { healthy: true, now_ms: now, uncertainty_ms: 0 };
  } }));
  await assert.rejects(client.beginAuthorizationCode({ ...requestInput(), grant_expires_at_ms: now + 600_000 }), expectCode('expired_token'));
  assert.equal(signs, 1);
  assert.equal(parCalls, 0);
  await client.close();
});
