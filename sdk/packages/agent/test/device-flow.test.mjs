import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from 'node:crypto';
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
const REQUEST_NONCE = Buffer.alloc(32, 0x35).toString('base64url');
const HANDLE = Buffer.alloc(32, 0x1c).toString('base64url');
const DPOP_NONCE = Buffer.alloc(32, 0x41).toString('base64url');
const DEVICE_CODE = 'D'.repeat(43);
const USER_CODE = 'BCDF-GHJK';
const REFRESH = 'R'.repeat(43);
const ACCESS = `${Buffer.from('{"alg":"RS256"}').toString('base64url')}.${Buffer.from('{"sub":"owner"}').toString('base64url')}.${'A'.repeat(342)}`;
const START = 1_700_000_000_123;

let now = START;

function openssl(dir, ...args) { execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' }); }
function certificates() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'atum-agent-device-flow-'));
  writeFileSync(path.join(dir, 'server.ext'), 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n');
  openssl(dir, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-subj', '/CN=atum-agent-device-flow-ca');
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
  const bytes = Buffer.from(JSON.stringify(value));
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': String(bytes.length), 'cache-control': 'no-store', ...extra });
  res.end(bytes);
}
async function body(req) { const chunks = []; for await (const chunk of req) chunks.push(chunk); return Buffer.concat(chunks); }
function hash(domain, value) { return `sha256:${createHash('sha256').update(domain, 'ascii').update(canonical(value), 'utf8').digest('hex')}`; }
function profile(origin) { const registration = structuredClone(vector.registry.registration); registration.issuer = origin; return { registration, client: structuredClone(vector.registry.clients[0]) }; }
function endpoints(origin) { return { options_url: `${origin}/atum/request/options`, verify_url: `${origin}/atum/request/verify`, par_url: `${origin}/request`, authorization_url: `${origin}/auth`, device_authorization_url: `${origin}/device/auth`, token_url: `${origin}/token` }; }
function input(grantExpires = START + 299_877) { const detail = vector.input.authorization_details[0]; return { permissions: structuredClone(detail.permissions), grant_limit: detail.grant_limit, grant_expires_at_ms: grantExpires }; }
function normalized(options, registration) {
  const detail = options.authorization_details[0];
  return { profile: 'atum-oauth-request-v1', request_id: REQUEST_ID, created_at_ms: now,
    expires_at_ms: Math.floor(Math.min(now + 300_000, detail.grant_expires_at_ms) / 1000) * 1000,
    issuer: registration.issuer, environment: 'sandbox', flow: 'device_code', client_id: options.client_id,
    registration: { ...registration, account_required_actions: [...registration.account_required_actions].sort() },
    resource: registration.audience, scope: 'atum:invoke', permissions: detail.permissions,
    grant_limit: detail.grant_limit, grant_expires_at_ms: detail.grant_expires_at_ms, code: null };
}
function preparedResponse(options, registration) { const request = normalized(options, registration); return { request,
  request_hash: hash('atum.oauth.request.v1\n', request), challenge_id: CHALLENGE_ID, nonce: REQUEST_NONCE,
  iat: Math.floor(request.created_at_ms / 1000), exp: request.expires_at_ms / 1000 }; }
function verifyResponse(prepared) { return { atum_request: HANDLE, request_id: prepared.request.request_id,
  request_hash: prepared.request_hash, agent_key_thumbprint: vector.expected.agent_key_thumbprint,
  state: 'verified', expires_at_ms: prepared.request.expires_at_ms }; }
function details(request) { return [{ type: 'atum', permissions: request.permissions,
  grant_limit: request.grant_limit, grant_expires_at_ms: request.grant_expires_at_ms }]; }
function tokens(request) { return { access_token: ACCESS, expires_in: 60, refresh_token: REFRESH,
  scope: 'atum:invoke', token_type: 'DPoP', authorization_details: details(request) }; }
function device(origin, changes = {}) { return { device_code: DEVICE_CODE, user_code: USER_CODE,
  verification_uri: `${origin}/device`, verification_uri_complete: `${origin}/device?user_code=${USER_CODE}`,
  expires_in: 120, ...changes };
}
function decodeProof(value) {
  const [header, claims, signature] = value.split('.');
  assert.equal(nodeVerify('sha256', Buffer.from(`${header}.${claims}`), { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64url')), true);
  return { header: JSON.parse(Buffer.from(header, 'base64url')), claims: JSON.parse(Buffer.from(claims, 'base64url')) };
}
async function key() { return createAgentKey({ publicJwk, sign: async data => nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' }) }); }
function config(h, agentKey, extra = {}) { const { registration, client } = profile(h.origin); return { registration, client,
  endpoints: endpoints(h.origin), tls: { ca: h.certs.ca }, key: agentKey,
  clock: () => ({ healthy: true, now_ms: now, uncertainty_ms: 0 }), timeoutMs: 500, maxConcurrent: 2, ...extra }; }
function expectCode(code) { return error => error instanceof AgentError && error.code === code; }
async function immediate() { await new Promise(resolve => setImmediate(resolve)); }
async function settleNetwork() { await immediate(); await immediate(); await immediate(); }
async function until(predicate, rounds = 200) {
  for (let index = 0; index < rounds; index += 1) { if (predicate()) return; await immediate(); }
  assert.fail('condition was not reached');
}
async function advance(t, milliseconds) { now += milliseconds; t.mock.timers.tick(milliseconds); await immediate(); }

function deviceHost(h, behavior = {}) {
  let prepared; let deviceForm; let tokenCalls = 0; const tokenTimes = [];
  const handler = async (req, res) => {
    const raw = await body(req); const { registration, client } = profile(h.origin);
    if (req.url === '/atum/request/options') {
      const options = JSON.parse(raw); assert.equal(options.flow, 'device_code'); assert.equal(options.code, null);
      prepared = preparedResponse(options, registration); return json(res, 200, prepared);
    }
    if (req.url === '/atum/request/verify') return json(res, 200, verifyResponse(prepared));
    if (req.url === '/device/auth') {
      deviceForm = Object.fromEntries(new URLSearchParams(raw.toString('utf8'))); const proof = decodeProof(req.headers.dpop);
      assert.deepEqual(Object.keys(deviceForm).sort(), ['atum_request', 'authorization_details', 'client_id', 'resource', 'scope']);
      assert.equal(deviceForm.atum_request, HANDLE); assert.equal(deviceForm.client_id, client.client_id);
      assert.equal(deviceForm.resource, registration.audience); assert.equal(deviceForm.scope, 'atum:invoke');
      assert.deepEqual(JSON.parse(deviceForm.authorization_details), details(prepared.request));
      assert.deepEqual(Object.keys(proof.claims).sort(), ['htm', 'htu', 'iat', 'jti']);
      assert.equal(proof.claims.htm, 'POST'); assert.equal(proof.claims.htu, `${h.origin}/device/auth`);
      if (behavior.beforeDeviceResponse) await behavior.beforeDeviceResponse({ req, res, prepared, origin: h.origin });
      if (res.destroyed) return;
      const deviceStatus = typeof behavior.deviceStatus === 'function' ? behavior.deviceStatus() : behavior.deviceStatus;
      return json(res, deviceStatus ?? 200, behavior.deviceResponse?.(h.origin, prepared) ?? device(h.origin));
    }
    assert.equal(req.url, '/token'); tokenCalls += 1; tokenTimes.push(now);
    const form = Object.fromEntries(new URLSearchParams(raw.toString('utf8'))); const proof = decodeProof(req.headers.dpop);
    assert.equal(form.grant_type, 'urn:ietf:params:oauth:grant-type:device_code');
    assert.equal(form.device_code, DEVICE_CODE); assert.equal(proof.claims.htu, `${h.origin}/token`);
    if (behavior.rawToken && behavior.rawToken({ req, res, raw, tokenCalls, prepared, origin: h.origin }) === true) return;
    if (tokenCalls % 2 === 1) {
      assert.equal(proof.claims.nonce, undefined);
      return json(res, 400, { error: 'use_dpop_nonce' }, { 'dpop-nonce': DPOP_NONCE });
    }
    assert.equal(proof.claims.nonce, DPOP_NONCE);
    if (behavior.tokenResponse) return behavior.tokenResponse({ res, attempt: tokenCalls / 2, prepared, origin: h.origin });
    return json(res, 200, tokens(prepared.request));
  };
  return { handler, state: () => ({ prepared, deviceForm, tokenCalls, tokenTimes: [...tokenTimes] }) };
}

test('real TLS Device begin binds the exact native request and applies the absent-interval default', async t => {
  now = START;
  let fixture;
  const h = await host((req, res) => fixture.handler(req, res)); t.after(h.close);
  fixture = deviceHost(h);
  const client = await createAgentClient(config(h, await key())); t.after(() => client.close());
  const flow = await client.beginDeviceAuthorization(input());
  assert.deepEqual(Object.keys(flow).sort(), ['expires_at_ms', 'interval_ms', 'poll', 'request_id', 'user_code', 'verification_uri', 'verification_uri_complete']);
  assert.equal(flow.request_id, REQUEST_ID); assert.equal(flow.user_code, USER_CODE);
  assert.equal(flow.verification_uri, `${h.origin}/device`);
  assert.equal(flow.verification_uri_complete, `${h.origin}/device?user_code=${USER_CODE}`);
  assert.equal(flow.expires_at_ms, START + 120_000); assert.equal(flow.interval_ms, 5_000);
  assert.equal(Object.isFrozen(flow), true); assert.equal(fixture.state().tokenCalls, 0);
});

test('Device deadline starts at the pre-request lower clock bound and response delay cannot extend it', async t => {
  now = START;
  let fixture;
  const h = await host((req, res) => fixture.handler(req, res)); t.after(h.close);
  fixture = deviceHost(h, { beforeDeviceResponse: async () => {
    await new Promise(resolve => setTimeout(resolve, 30)); now += 100;
  }, deviceResponse: origin => device(origin, { expires_in: 10 }) });
  const client = await createAgentClient(config(h, await key(), {
    clock: () => ({ healthy: true, now_ms: now, uncertainty_ms: 250 }),
  })); t.after(() => client.close());
  const flow = await client.beginDeviceAuthorization(input());
  assert.equal(flow.expires_at_ms, START - 250 + 10_000);
  assert.ok(flow.expires_at_ms < now + 10_000);
  assert.equal(fixture.state().tokenCalls, 0);
});

test('poll waits first, preserves pending interval, applies each slowdown, then returns one exact token set', async t => {
  now = START; t.mock.timers.enable({ apis: ['setTimeout'] });
  let fixture;
  const h = await host((req, res) => fixture.handler(req, res)); t.after(h.close);
  fixture = deviceHost(h, { tokenResponse: ({ res, attempt, prepared }) => {
    if (attempt === 1) return json(res, 400, { error: 'authorization_pending', error_description: 'private owner state' });
    if (attempt === 2) return json(res, 400, { error: 'slow_down' });
    return json(res, 200, tokens(prepared.request));
  } });
  const client = await createAgentClient(config(h, await key(), { timeoutMs: 5_000 })); t.after(() => client.close());
  const flow = await client.beginDeviceAuthorization(input());
  const controller = new AbortController(); const polling = flow.poll({ signal: controller.signal });
  await immediate(); assert.equal(fixture.state().tokenCalls, 0);
  await advance(t, 4_999); assert.equal(fixture.state().tokenCalls, 0);
  await advance(t, 1); await until(() => fixture.state().tokenCalls === 2); await settleNetwork();
  await advance(t, 5_000); await until(() => fixture.state().tokenCalls === 4); await settleNetwork();
  await advance(t, 9_999); assert.equal(fixture.state().tokenCalls, 4);
  await advance(t, 1); const result = await polling;
  assert.equal(result.refresh_token, REFRESH); assert.equal(fixture.state().tokenCalls, 6);
  assert.deepEqual(fixture.state().tokenTimes.filter((_value, index) => index % 2 === 0),
    [START + 5_000, START + 10_000, START + 20_000]);
  await assert.rejects(flow.poll({ signal: new AbortController().signal }), expectCode('invalid_request'));
});

test('abort is unavailable, permits no future poll HTTP, and discards an in-flight success', async t => {
  now = START; t.mock.timers.enable({ apis: ['setTimeout'] });
  let fixture; let releaseSuccess; let successEntered = false;
  const h = await host((req, res) => fixture.handler(req, res)); t.after(h.close);
  fixture = deviceHost(h, { tokenResponse: ({ res, prepared }) => {
    successEntered = true; releaseSuccess = () => json(res, 200, tokens(prepared.request));
  } });
  const client = await createAgentClient(config(h, await key(), { timeoutMs: 5_000 })); t.after(() => client.close());
  const flow = await client.beginDeviceAuthorization(input());
  const controller = new AbortController(); const polling = flow.poll({ signal: controller.signal });
  await advance(t, 5_000); await until(() => successEntered);
  controller.abort(); releaseSuccess();
  await assert.rejects(polling, expectCode('temporarily_unavailable'));
  await advance(t, 30_000); assert.equal(fixture.state().tokenCalls, 2);

  const second = await client.beginDeviceAuthorization(input());
  const waiting = new AbortController(); const pending = second.poll({ signal: waiting.signal });
  const concurrent = second.poll({ signal: new AbortController().signal });
  await assert.rejects(concurrent, expectCode('invalid_request'));
  waiting.abort(); await assert.rejects(pending, expectCode('temporarily_unavailable'));
  assert.equal(fixture.state().tokenCalls, 2);
});

test('abort before a nonce response fences the continuation and forged signals fail before token HTTP', async t => {
  now = START; t.mock.timers.enable({ apis: ['setTimeout'] });
  let fixture; let firstResponse; let firstEntered;
  const entered = new Promise(resolve => { firstEntered = resolve; });
  const h = await host((req, res) => fixture.handler(req, res)); t.after(h.close);
  fixture = deviceHost(h, { rawToken: ({ res, tokenCalls }) => {
    if (tokenCalls !== 1) return false;
    firstResponse = res; firstEntered(); return true;
  } });
  const client = await createAgentClient(config(h, await key(), { timeoutMs: 5_000 })); t.after(() => client.close());
  const flow = await client.beginDeviceAuthorization(input());
  const controller = new AbortController();
  controller.signal.addEventListener('abort', event => event.stopImmediatePropagation());
  const polling = flow.poll({ signal: controller.signal }); polling.catch(() => {});
  await advance(t, 5_000); await entered;
  controller.abort();
  json(firstResponse, 400, { error: 'use_dpop_nonce' }, { 'dpop-nonce': DPOP_NONCE });
  await assert.rejects(polling, expectCode('temporarily_unavailable'));
  await settleNetwork(); await advance(t, 30_000);
  assert.equal(fixture.state().tokenCalls, 1);

  const second = await client.beginDeviceAuthorization(input());
  let ownAccess = 0;
  const forged = Object.create(AbortSignal.prototype, {
    aborted: { configurable: true, get() { ownAccess += 1; return false; } },
    addEventListener: { configurable: true, value() { ownAccess += 1; } },
    removeEventListener: { configurable: true, value() { ownAccess += 1; } },
  });
  const forgedPolling = second.poll({ signal: forged }); forgedPolling.catch(() => {});
  assert.equal(ownAccess, 0);
  await assert.rejects(forgedPolling, expectCode('invalid_request'));
  assert.equal(fixture.state().tokenCalls, 1);
});

test('an expiry wake-up cannot shorten the server polling interval when clock uncertainty shrinks', async t => {
  now = START; t.mock.timers.enable({ apis: ['setTimeout'] }); let uncertainty = 1_000;
  let fixture;
  const h = await host((req, res) => fixture.handler(req, res)); t.after(h.close);
  fixture = deviceHost(h, { deviceResponse: origin => device(origin, { expires_in: 6 }) });
  const client = await createAgentClient(config(h, await key(), {
    timeoutMs: 5_000, clock: () => ({ healthy: true, now_ms: now, uncertainty_ms: uncertainty }),
  })); t.after(() => client.close());
  const flow = await client.beginDeviceAuthorization(input());
  uncertainty = 0;
  const polling = flow.poll({ signal: new AbortController().signal }); polling.catch(() => {});
  await advance(t, 4_000); await settleNetwork();
  assert.equal(fixture.state().tokenCalls, 0);
  await advance(t, 1_000); await assert.rejects(polling, expectCode('expired_token'));
  assert.equal(fixture.state().tokenCalls, 0);
});

test('genuine AbortSignal shadow properties are never invoked by polling setup or disposal', async t => {
  now = START; t.mock.timers.enable({ apis: ['setTimeout'] }); let accesses = 0;
  let fixture;
  const h = await host((req, res) => fixture.handler(req, res)); t.after(h.close);
  fixture = deviceHost(h, { deviceResponse: origin => device(origin, { interval: 1 }) });
  const client = await createAgentClient(config(h, await key())); t.after(() => client.close());
  const flow = await client.beginDeviceAuthorization(input()); const controller = new AbortController();
  Object.defineProperties(controller.signal, {
    aborted: { configurable: true, get() { accesses += 1; throw new Error('synthetic private input'); } },
    addEventListener: { configurable: true, value() { accesses += 1; throw new Error('synthetic private input'); } },
    removeEventListener: { configurable: true, value() { accesses += 1; throw new Error('synthetic private input'); } },
  });
  const polling = flow.poll({ signal: controller.signal });
  await advance(t, 1_000); const token = await polling;
  assert.equal(token.refresh_token, REFRESH); assert.equal(accesses, 0); assert.equal(fixture.state().tokenCalls, 2);
});

test('token transport loss and a withheld response are terminal without retry or late success', async t => {
  now = START; t.mock.timers.enable({ apis: ['setTimeout'] });

  let lostFixture;
  const lostHost = await host((req, res) => lostFixture.handler(req, res));
  lostFixture = deviceHost(lostHost, { rawToken: ({ res, tokenCalls }) => {
    if (tokenCalls !== 1) return false;
    res.socket.destroy(); return true;
  } });
  const lostClient = await createAgentClient(config(lostHost, await key()));
  try {
    const lost = await lostClient.beginDeviceAuthorization(input());
    const polling = lost.poll({ signal: new AbortController().signal }); polling.catch(() => {});
    await advance(t, 5_000); await assert.rejects(polling, expectCode('temporarily_unavailable'));
    await advance(t, 30_000); assert.equal(lostFixture.state().tokenCalls, 1);
  } finally { await lostClient.close(); await lostHost.close(); }

  now = START; let heldResponse; let withheldFixture;
  const withheldHost = await host((req, res) => withheldFixture.handler(req, res));
  withheldFixture = deviceHost(withheldHost, { rawToken: ({ res, tokenCalls }) => {
    if (tokenCalls !== 1) return false;
    heldResponse = res; return true;
  } });
  const withheldClient = await createAgentClient(config(withheldHost, await key()));
  try {
    const withheld = await withheldClient.beginDeviceAuthorization(input());
    const polling = withheld.poll({ signal: new AbortController().signal }); polling.catch(() => {});
    await advance(t, 5_000); await until(() => heldResponse !== undefined);
    await advance(t, 501); await assert.rejects(polling, expectCode('temporarily_unavailable'));
    try { json(heldResponse, 200, tokens(withheldFixture.state().prepared.request)); } catch { /* timed-out socket is not recoverable */ }
    await immediate(); await advance(t, 30_000);
    assert.equal(withheldFixture.state().tokenCalls, 1);
  } finally { await withheldClient.close(); await withheldHost.close(); }
});

test('server and prepared-request expiries stop polling before another token request', async t => {
  now = START; t.mock.timers.enable({ apis: ['setTimeout'] });
  let mode = 'server'; let fixture;
  const h = await host((req, res) => fixture.handler(req, res)); t.after(h.close);
  fixture = deviceHost(h, { deviceResponse: origin => mode === 'server'
    ? device(origin, { expires_in: 1 })
    : device(origin, { expires_in: 300, interval: 300 }) });
  const client = await createAgentClient(config(h, await key(), { timeoutMs: 5_000 })); t.after(() => client.close());
  const serverExpiry = await client.beginDeviceAuthorization(input());
  const first = serverExpiry.poll({ signal: new AbortController().signal }); first.catch(() => {});
  await advance(t, 1_000); await assert.rejects(first, expectCode('expired_token'));
  assert.equal(fixture.state().tokenCalls, 0);

  mode = 'request';
  const requestExpiry = await client.beginDeviceAuthorization(input());
  assert.equal(requestExpiry.expires_at_ms, Math.floor((START + 299_877) / 1000) * 1000);
  assert.equal(requestExpiry.interval_ms, 300_000);
  const second = requestExpiry.poll({ signal: new AbortController().signal }); second.catch(() => {});
  await advance(t, requestExpiry.expires_at_ms - now);
  await assert.rejects(second, expectCode('expired_token'));
  assert.equal(fixture.state().tokenCalls, 0);
});

test('close during a stalled Device begin rejects the operation and cannot return a late handle', async t => {
  now = START; let release; let entered; let fixture;
  const responseEntered = new Promise(resolve => { entered = resolve; });
  const h = await host((req, res) => fixture.handler(req, res)); t.after(h.close);
  fixture = deviceHost(h, { beforeDeviceResponse: async () => {
    entered(); await new Promise(resolve => { release = resolve; });
  } });
  const client = await createAgentClient(config(h, await key(), { timeoutMs: 5_000 }));
  const beginning = client.beginDeviceAuthorization(input());
  await responseEntered;
  const closing = client.close();
  await assert.rejects(beginning, expectCode('temporarily_unavailable'));
  release(); await closing; await immediate();
  assert.equal(fixture.state().tokenCalls, 0);
  await assert.rejects(client.beginDeviceAuthorization(input()), expectCode('temporarily_unavailable'));
});

test('malformed Device URLs, interval and response additions fail terminally before polling', async t => {
  now = START; let response = origin => device(origin); let status = 200; let fixture;
  const h = await host((req, res) => fixture.handler(req, res)); t.after(h.close);
  fixture = deviceHost(h, { deviceStatus: () => status,
    deviceResponse: (origin, prepared) => response(origin, prepared) });
  const client = await createAgentClient(config(h, await key())); t.after(() => client.close());
  const cases = [
    origin => ({ ...device(origin), extra: true }),
    origin => device(origin, { interval: 0 }),
    origin => device(origin, { interval: 301 }),
    origin => device(origin, { interval: 1.5 }),
    origin => device(origin, { user_code: 'ABCD-EFGH', verification_uri_complete: `${origin}/device?user_code=ABCD-EFGH` }),
    origin => device(origin, { verification_uri: 'https://other.example/device' }),
    origin => device(origin, { verification_uri: `${origin.replace('https://', 'https://user@')}/device` }),
    origin => device(origin, { verification_uri: `${origin}/device#fragment` }),
    origin => device(origin, { verification_uri: `${origin}/device?` }),
    origin => device(origin, { verification_uri: `${origin}/device#` }),
    origin => device(origin, { verification_uri_complete: `${origin.replace('https://', 'https://user@')}/device?user_code=${USER_CODE}` }),
    origin => device(origin, { verification_uri_complete: `${origin}/device?user_code=${USER_CODE}#fragment` }),
    origin => device(origin, { verification_uri_complete: `${origin}/device?user_code=${USER_CODE}#` }),
    origin => device(origin, { verification_uri_complete: `${origin}/device?user_code=${USER_CODE}&user_code=${USER_CODE}` }),
    origin => device(origin, { verification_uri_complete: `${origin}/device?user_code=${USER_CODE}&return=https://other.example` }),
    origin => device(origin, { verification_uri_complete: `${origin}/device?user_code=WRONG-CODE` }),
    origin => device(origin, { expires_in: 0 }),
    origin => device(origin, { expires_in: 301 }),
  ];
  for (const candidate of cases) {
    response = candidate;
    await assert.rejects(client.beginDeviceAuthorization(input()), expectCode('temporarily_unavailable'));
  }
  response = origin => device(origin); status = 400;
  await assert.rejects(client.beginDeviceAuthorization(input()), expectCode('temporarily_unavailable'));
  assert.equal(fixture.state().tokenCalls, 0);
});

test('close and malformed authenticated polling errors settle the handle without retrying', async t => {
  now = START; t.mock.timers.enable({ apis: ['setTimeout'] });
  let malformed = false; let fixture;
  const h = await host((req, res) => fixture.handler(req, res)); t.after(h.close);
  fixture = deviceHost(h, { tokenResponse: ({ res }) => malformed
    ? json(res, 400, { error: 'authorization_pending', extra: true })
    : json(res, 400, { error: 'access_denied', error_description: 'private owner reason' }) });
  const client = await createAgentClient(config(h, await key(), { timeoutMs: 5_000 }));
  const denied = await client.beginDeviceAuthorization(input());
  const deniedPoll = denied.poll({ signal: new AbortController().signal });
  await advance(t, 5_000); await assert.rejects(deniedPoll, expectCode('access_denied'));
  assert.equal(fixture.state().tokenCalls, 2);

  malformed = true;
  const bad = await client.beginDeviceAuthorization(input()); const badPoll = bad.poll({ signal: new AbortController().signal });
  await advance(t, 5_000); await assert.rejects(badPoll, expectCode('temporarily_unavailable'));
  assert.equal(fixture.state().tokenCalls, 4);

  const waiting = await client.beginDeviceAuthorization(input());
  const pending = waiting.poll({ signal: new AbortController().signal });
  await client.close();
  await assert.rejects(pending, expectCode('temporarily_unavailable'));
  await advance(t, 30_000); assert.equal(fixture.state().tokenCalls, 4);
});
