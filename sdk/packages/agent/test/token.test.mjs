import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';

import { AgentError, createAgentKey } from '../src/index.mjs';
import { canonical } from '../src/strict.mjs';
import { createTokenClient } from '../src/token.mjs';

const vector = JSON.parse(readFileSync(new URL('../../../protocol/owner-consent/owner-consent-v1.json', import.meta.url)));
const privateJwk = vector.test_private_jwk;
const publicJwk = { kty: privateJwk.kty, crv: privateJwk.crv, x: privateJwk.x, y: privateJwk.y };
const privateKey = createPrivateKey({ key: privateJwk, format: 'jwk' });
const publicKey = createPublicKey({ key: publicJwk, format: 'jwk' });
const NOW = 1_700_000_000_123;
const NONCE = Buffer.alloc(32, 0x35).toString('base64url');
const CODE = 'C'.repeat(43);
const DEVICE_CODE = 'D'.repeat(43);
const REFRESH = 'R'.repeat(43);
const ROTATED = 'S'.repeat(43);
const VERIFIER = Buffer.alloc(32, 0x27).toString('base64url');
const ACCESS = `${Buffer.from('{"alg":"RS256"}').toString('base64url')}.${Buffer.from('{"sub":"owner"}').toString('base64url')}.${'A'.repeat(342)}`;

function openssl(dir, ...args) { execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' }); }
function certificates() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'atum-agent-token-'));
  writeFileSync(path.join(dir, 'server.ext'), 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n');
  openssl(dir, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-subj', '/CN=atum-agent-token-ca');
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
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': String(body.length), 'cache-control': 'no-store', ...extra });
  res.end(body);
}
async function requestBody(req) { const chunks = []; for await (const chunk of req) chunks.push(chunk); return Buffer.concat(chunks).toString('utf8'); }
function details() {
  const value = structuredClone(vector.input.authorization_details);
  value[0].grant_expires_at_ms = NOW + 240_000;
  value[0].permissions.sort((left, right) => left.action < right.action ? -1 : left.action > right.action ? 1 : 0);
  return value;
}
function token(expected = details(), refresh = ROTATED) {
  return { access_token: ACCESS, expires_in: 60, refresh_token: refresh, scope: 'atum:invoke', token_type: 'DPoP', authorization_details: expected };
}
async function key(sign = async data => nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' }), timeoutMs = 500) {
  return createAgentKey({ publicJwk, sign, timeoutMs });
}
function config(h, agentKey, extra = {}) {
  return { client_id: vector.registry.clients[0].client_id, token_url: `${h.origin}/token`, tls: { ca: h.certs.ca }, key: agentKey,
    clock: () => ({ healthy: true, now_ms: NOW, uncertainty_ms: 0 }), timeoutMs: 500, maxConcurrent: 2, ...extra };
}
function expectCode(code) { return error => error instanceof AgentError && error.code === code && !error.message.includes('secret'); }
function decodeDpop(value) {
  const parts = value.split('.'); assert.equal(parts.length, 3);
  const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
  assert.equal(nodeVerify('sha256', Buffer.from(`${parts[0]}.${parts[1]}`), { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(parts[2], 'base64url')), true);
  return { header, claims };
}

test('code, Device and refresh use exact forms and one bounded DPoP nonce continuation', async t => {
  const seen = [];
  const expected = details();
  const h = await host(async (req, res) => {
    const body = await requestBody(req); const proof = decodeDpop(req.headers.dpop);
    seen.push({ method: req.method, url: req.url, headers: req.headers, body, proof });
    assert.deepEqual(proof.header, { alg: 'ES256', jwk: publicJwk, typ: 'dpop+jwt' });
    assert.equal(proof.claims.htm, 'POST'); assert.equal(proof.claims.htu, `${h.origin}/token`); assert.equal(proof.claims.iat, Math.floor(NOW / 1000));
    assert.match(proof.claims.jti, /^[A-Za-z0-9_-]{22}$/);
    if (proof.claims.nonce === undefined) return json(res, 400, { error: 'use_dpop_nonce', error_description: 'nonce required' }, { 'dpop-nonce': NONCE });
    assert.equal(proof.claims.nonce, NONCE);
    return json(res, 200, token(expected, body.includes('grant_type=refresh_token') ? ROTATED : REFRESH));
  });
  t.after(h.close);
  const client = createTokenClient(config(h, await key()));
  const codeResult = await client.exchangeCode({ code: CODE, code_verifier: VERIFIER, redirect_uri: vector.input.code.redirect_uri, expected_authorization_details: expected });
  const deviceResult = await client.exchangeDevice({ device_code: DEVICE_CODE, expected_authorization_details: expected });
  const refreshResult = await client.refresh({ refresh_token: REFRESH, expected_authorization_details: expected });
  assert.deepEqual(seen.map(item => item.body), [
    `grant_type=authorization_code&client_id=agent-1&code=${CODE}&redirect_uri=https%3A%2F%2Fagent.example%2Fcallback&code_verifier=${VERIFIER}`,
    `grant_type=authorization_code&client_id=agent-1&code=${CODE}&redirect_uri=https%3A%2F%2Fagent.example%2Fcallback&code_verifier=${VERIFIER}`,
    `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&client_id=agent-1&device_code=${DEVICE_CODE}`,
    `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&client_id=agent-1&device_code=${DEVICE_CODE}`,
    `grant_type=refresh_token&client_id=agent-1&refresh_token=${REFRESH}`,
    `grant_type=refresh_token&client_id=agent-1&refresh_token=${REFRESH}`,
  ]);
  assert.equal(new Set(seen.map(item => item.proof.claims.jti)).size, 6);
  for (const item of seen) {
    assert.equal(item.method, 'POST'); assert.equal(item.url, '/token');
    assert.equal(item.headers['content-type'], 'application/x-www-form-urlencoded');
    assert.equal(item.headers.authorization, undefined); assert.equal(item.headers.cookie, undefined); assert.equal(item.headers['proxy-authorization'], undefined);
  }
  for (const result of [codeResult, deviceResult, refreshResult]) {
    assert.equal(result.token_type, 'DPoP'); assert.equal(result.scope, 'atum:invoke'); assert.equal(Object.isFrozen(result), true);
    assert.equal(Object.isFrozen(result.authorization_details[0].permissions), true);
  }
  assert.equal(codeResult.refresh_token, REFRESH); assert.equal(deviceResult.refresh_token, REFRESH); assert.equal(refreshResult.refresh_token, ROTATED);
  await client.close();
});

test('known OAuth errors are closed, descriptions are discarded and Device polling states are internal results', async t => {
  let behavior = 'invalid-first'; let calls = 0;
  const h = await host(async (req, res) => {
    await requestBody(req); calls += 1; const proof = decodeDpop(req.headers.dpop);
    if (behavior === 'invalid-first') return json(res, 400, { error: 'invalid_grant', error_description: 'secret old token detail' });
    if (proof.claims.nonce === undefined) return json(res, 400, { error: 'use_dpop_nonce' }, { 'dpop-nonce': NONCE });
    if (behavior === 'pending') return json(res, 400, { error: 'authorization_pending', error_description: 'owner detail' });
    if (behavior === 'slow') return json(res, 400, { error: 'slow_down' });
    if (behavior === 'expired') return json(res, 400, { error: 'expired_token', error_description: 'device detail' });
    if (behavior === 'proof') return json(res, 400, { error: 'invalid_dpop_proof', error_description: 'proof detail' });
    if (behavior === 'extra') return json(res, 400, { error: 'invalid_grant', error_description: 'x', extra: true });
    return json(res, 500, { error: 'server_error', error_description: 'private stack' });
  });
  t.after(h.close);
  const client = createTokenClient(config(h, await key())); const expected = details();
  await assert.rejects(client.refresh({ refresh_token: REFRESH, expected_authorization_details: expected }), expectCode('invalid_grant')); assert.equal(calls, 1);
  behavior = 'pending'; assert.deepEqual(await client.exchangeDevice({ device_code: DEVICE_CODE, expected_authorization_details: expected }), { state: 'authorization_pending' });
  behavior = 'slow'; assert.deepEqual(await client.exchangeDevice({ device_code: DEVICE_CODE, expected_authorization_details: expected }), { state: 'slow_down' });
  behavior = 'expired'; await assert.rejects(client.exchangeDevice({ device_code: DEVICE_CODE, expected_authorization_details: expected }), expectCode('expired_token'));
  behavior = 'proof'; await assert.rejects(client.refresh({ refresh_token: REFRESH, expected_authorization_details: expected }), expectCode('invalid_proof'));
  behavior = 'extra'; await assert.rejects(client.refresh({ refresh_token: REFRESH, expected_authorization_details: expected }), expectCode('temporarily_unavailable'));
  behavior = 'server'; await assert.rejects(client.refresh({ refresh_token: REFRESH, expected_authorization_details: expected }), expectCode('temporarily_unavailable'));
  await client.close();
});

test('malformed nonce, substituted RAR and ambiguous refresh response never trigger an extra request', async t => {
  let behavior = 'nonce'; let calls = 0;
  const expected = details();
  const h = await host(async (req, res) => {
    await requestBody(req); calls += 1; const proof = decodeDpop(req.headers.dpop); const current = behavior;
    if (current === 'nonce') return json(res, 400, { error: 'use_dpop_nonce' }, { 'dpop-nonce': 'not-canonical' });
    if (current === 'duplicate-nonce') return json(res, 400, { error: 'use_dpop_nonce' }, { 'dpop-nonce': [NONCE, NONCE] });
    if (current === 'first-success') return json(res, 200, token(expected, ROTATED));
    if (current === 'redirect') return json(res, 302, { error: 'use_dpop_nonce' }, { location: '/elsewhere', 'dpop-nonce': NONCE });
    if (current === 'truncated') {
      res.writeHead(400, { 'content-type': 'application/json', 'content-length': '100', 'cache-control': 'no-store', 'dpop-nonce': NONCE });
      res.write('{"error":'); return res.socket.destroy();
    }
    if (current === 'delayed') { await delay(550); return json(res, 400, { error: 'use_dpop_nonce' }, { 'dpop-nonce': NONCE }); }
    if (proof.claims.nonce === undefined) return json(res, 400, { error: 'use_dpop_nonce' }, { 'dpop-nonce': NONCE });
    if (current === 'rar') return json(res, 200, token([{ ...expected[0], grant_limit: expected[0].grant_limit + 1 }], ROTATED));
    if (current === 'second-challenge') return json(res, 400, { error: 'use_dpop_nonce' }, { 'dpop-nonce': NONCE });
    return res.socket.destroy();
  });
  t.after(h.close);
  const client = createTokenClient(config(h, await key()));
  await assert.rejects(client.refresh({ refresh_token: REFRESH, expected_authorization_details: expected }), expectCode('temporarily_unavailable')); assert.equal(calls, 1);
  behavior = 'rar'; const beforeRar = calls; await assert.rejects(client.refresh({ refresh_token: REFRESH, expected_authorization_details: expected }), expectCode('temporarily_unavailable')); assert.equal(calls - beforeRar, 2);
  behavior = 'second-challenge'; const beforeChallenge = calls; await assert.rejects(client.refresh({ refresh_token: REFRESH, expected_authorization_details: expected }), expectCode('temporarily_unavailable')); assert.equal(calls - beforeChallenge, 2);
  behavior = 'close'; const beforeClose = calls; await assert.rejects(client.refresh({ refresh_token: REFRESH, expected_authorization_details: expected }), expectCode('temporarily_unavailable')); assert.equal(calls - beforeClose, 2);
  for (const next of ['duplicate-nonce', 'first-success', 'redirect', 'truncated', 'delayed']) {
    behavior = next; const before = calls;
    await assert.rejects(client.refresh({ refresh_token: REFRESH, expected_authorization_details: expected }), expectCode('temporarily_unavailable'));
    assert.equal(calls - before, 1, next);
  }
  await client.close();
});

test('whole logical capacity includes a stalled signer and close fences late token HTTP', async t => {
  let calls = 0; let release;
  const h = await host(async (_req, res) => { calls += 1; json(res, 500, {}); }); t.after(h.close);
  const stalled = await key(async data => new Promise(resolve => { release = () => resolve(nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' })); }), 500);
  const client = createTokenClient(config(h, stalled, { timeoutMs: 500, maxConcurrent: 1 }));
  const first = client.refresh({ refresh_token: REFRESH, expected_authorization_details: details() }); first.catch(() => {});
  while (!release) await delay(1);
  await assert.rejects(client.exchangeDevice({ device_code: DEVICE_CODE, expected_authorization_details: details() }), expectCode('temporarily_unavailable'));
  const closed = client.close(); await assert.rejects(first, expectCode('temporarily_unavailable')); await closed;
  release(); await delay(30); assert.equal(calls, 0);
  await assert.rejects(client.refresh({ refresh_token: REFRESH, expected_authorization_details: details() }), expectCode('temporarily_unavailable'));
  const never = await key(async () => new Promise(() => {}), 500);
  const bounded = createTokenClient(config(h, never, { timeoutMs: 100, maxConcurrent: 1 }));
  const started = performance.now();
  await assert.rejects(bounded.refresh({ refresh_token: REFRESH, expected_authorization_details: details() }), expectCode('temporarily_unavailable'));
  assert.ok(performance.now() - started < 300); assert.equal(calls, 0); await bounded.close();
});

test('the immutable grant expiry fences a late signer, nonce retry and token result', async t => {
  let calls = 0; let now = NOW;
  const expected = details(); expected[0].grant_expires_at_ms = NOW + 10;
  const h = await host(async (req, res) => {
    await requestBody(req); calls += 1; now = NOW + 11;
    json(res, 400, { error: 'use_dpop_nonce' }, { 'dpop-nonce': NONCE });
  });
  t.after(h.close);
  const lateSigner = await key(async data => {
    now = NOW + 11;
    return nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  });
  const signerClient = createTokenClient(config(h, lateSigner, { clock: () => ({ healthy: true, now_ms: now, uncertainty_ms: 0 }) }));
  await assert.rejects(signerClient.refresh({ refresh_token: REFRESH, expected_authorization_details: expected }), expectCode('expired_token'));
  assert.equal(calls, 0); await signerClient.close();

  now = NOW;
  const responseClient = createTokenClient(config(h, await key(), { clock: () => ({ healthy: true, now_ms: now, uncertainty_ms: 0 }) }));
  await assert.rejects(responseClient.refresh({ refresh_token: REFRESH, expected_authorization_details: expected }), expectCode('expired_token'));
  assert.equal(calls, 1); await responseClient.close();
});

test('invalid configuration and caller input fail before signing or network without invoking accessors', async t => {
  let calls = 0; let signs = 0; let getters = 0;
  const h = await host((_req, res) => { calls += 1; json(res, 500, {}); }); t.after(h.close);
  const agentKey = await key(async data => { signs += 1; return nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' }); });
  assert.throws(() => createTokenClient(config(h, agentKey, { tls: { ca: 'not a PEM certificate' } })), TypeError);
  const foreign = certificates();
  t.after(() => rmSync(foreign.dir, { recursive: true, force: true }));
  const untrusted = createTokenClient(config(h, agentKey, { tls: { ca: foreign.ca } }));
  await assert.rejects(untrusted.refresh({ refresh_token: REFRESH, expected_authorization_details: details() }), expectCode('temporarily_unavailable'));
  await untrusted.close();
  const wrongHost = createTokenClient(config(h, agentKey, { token_url: `${h.origin.replace('localhost', '127.0.0.1')}/token` }));
  await assert.rejects(wrongHost.refresh({ refresh_token: REFRESH, expected_authorization_details: details() }), expectCode('temporarily_unavailable'));
  await wrongHost.close(); assert.equal(calls, 0);
  const signsBeforeInvalidInput = signs;
  const client = createTokenClient(config(h, agentKey));
  const accessor = { refresh_token: REFRESH, expected_authorization_details: details() };
  Object.defineProperty(accessor, 'refresh_token', { enumerable: true, get() { getters += 1; return REFRESH; } });
  const nullPrototype = Object.assign(Object.create(null), { refresh_token: REFRESH, expected_authorization_details: details() });
  const hidden = { refresh_token: REFRESH, expected_authorization_details: details() };
  Object.defineProperty(hidden, 'refresh_token', { value: REFRESH, enumerable: false });
  for (const value of [accessor, { refresh_token: 'short', expected_authorization_details: details() },
    { refresh_token: REFRESH, expected_authorization_details: details(), extra: true }, nullPrototype, hidden]) {
    await assert.rejects(client.refresh(value), expectCode('invalid_request'));
  }
  assert.equal(getters, 0); assert.equal(signs, signsBeforeInvalidInput); assert.equal(calls, 0);
  await client.close();
});
