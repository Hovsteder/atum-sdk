import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';

import { AgentError } from '../src/key.mjs';
import { createProtectedResourceTransport } from '../src/resource-transport.mjs';

const encoder = new TextEncoder();
const TOKEN = `eyJhbGciOiJSUzI1NiJ9.${'a'.repeat(43)}.${'b'.repeat(86)}`;
const DPOP = `eyJhbGciOiJFUzI1NiJ9.${'a'.repeat(43)}.${'b'.repeat(86)}`;

function openssl(dir, ...args) { execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' }); }
function certificates() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'atum-agent-resource-transport-'));
  writeFileSync(path.join(dir, 'server.ext'), 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n');
  openssl(dir, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-subj', '/CN=atum-agent-resource-ca');
  openssl(dir, 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'server.key', '-out', 'server.csr', '-subj', '/CN=localhost');
  openssl(dir, 'x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'server.pem', '-days', '1', '-extfile', 'server.ext');
  return { dir, ca: readFileSync(path.join(dir, 'ca.pem'), 'utf8'), cert: readFileSync(path.join(dir, 'server.pem')), key: readFileSync(path.join(dir, 'server.key')) };
}
async function host(handler, options = {}) {
  const certs = certificates();
  const server = https.createServer({ cert: certs.cert, key: certs.key, ...options }, handler);
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
function configuration(h, changes = {}) { return { endpoint: { method: 'POST', url: `${h.origin}/api/v1/atum/operations` }, tls: { ca: h.certs.ca }, timeoutMs: 120, maxConcurrent: 1, ...changes }; }
function artifact(h, changes = {}) { return { authorization: `DPoP ${TOKEN}`, dpop: DPOP, body: '{"action_request":{"amount":2},"context":{"operation_id":"operation-1"}}', method: 'POST', url: `${h.origin}/api/v1/atum/operations`, ...changes }; }
function deadline(milliseconds = 90) { return performance.now() + milliseconds; }
function unavailable(error) { return error instanceof AgentError && error.code === 'temporarily_unavailable'; }
function invalid(error) { return error instanceof AgentError && error.code === 'invalid_request'; }

test('posts a snapshotted exact artifact and returns opaque response headers', async t => {
  const seen = [];
  const h = await host(async (req, res) => {
    seen.push({ method: req.method, url: req.url, headers: req.headers, body: (await body(req)).toString('utf8') });
    json(res, 401, { error: 'use_dpop_nonce' }, { 'dpop-nonce': Buffer.alloc(32, 7).toString('base64url'), 'www-authenticate': 'DPoP error="use_dpop_nonce", algs="ES256"' });
  });
  t.after(h.close);
  const transport = createProtectedResourceTransport(configuration(h));
  const source = artifact(h); const pending = transport.post(source, deadline());
  source.body = '{}'; source.authorization = 'DPoP changed';
  const result = await pending;
  assert.equal(result.status, 401); assert.deepEqual(result.body, { error: 'use_dpop_nonce' });
  assert.equal(result.nonce, Buffer.alloc(32, 7).toString('base64url'));
  assert.equal(result.authenticate, 'DPoP error="use_dpop_nonce", algs="ES256"');
  assert.equal(Object.isFrozen(result), true); assert.equal(Object.isFrozen(result.body), true);
  assert.deepEqual(seen.map(item => [item.method, item.url, item.body]), [['POST', '/api/v1/atum/operations', artifact(h).body]]);
  const headers = seen[0].headers;
  assert.equal(headers.authorization, `DPoP ${TOKEN}`); assert.equal(headers.dpop, DPOP);
  assert.equal(headers['content-type'], 'application/json'); assert.equal(headers['content-length'], String(Buffer.byteLength(artifact(h).body)));
  assert.equal(headers.accept, 'application/json'); assert.equal(headers['cache-control'], 'no-store'); assert.equal(headers.connection, 'close');
  assert.equal(headers.cookie, undefined); assert.equal(headers['proxy-authorization'], undefined);
  await transport.close();
});

test('rejects invalid configuration and proof artifacts before resource network I/O', async t => {
  let calls = 0;
  const h = await host((_req, res) => { calls += 1; json(res, 200, {}); }); t.after(h.close);
  const valid = configuration(h);
  const defaults = createProtectedResourceTransport({ endpoint: valid.endpoint, tls: valid.tls });
  await defaults.close();
  for (const value of [
    { ...valid, endpoint: { ...valid.endpoint, method: 'GET' } },
    { ...valid, endpoint: { ...valid.endpoint, url: `${h.origin}/api?target=x` } },
    { ...valid, endpoint: { ...valid.endpoint, url: `${h.origin}/api?` } },
    { ...valid, endpoint: { ...valid.endpoint, url: `${h.origin}/api#` } },
    { ...valid, endpoint: { method: 'POST', url: `http://localhost:${new URL(h.origin).port}/api` } },
    { ...valid, tls: { ca: valid.tls.ca, extra: true } }, { ...valid, timeoutMs: 0 }, { ...valid, maxConcurrent: 17 },
  ]) assert.throws(() => createProtectedResourceTransport(value), TypeError);
  const accessor = configuration(h); Object.defineProperty(accessor, 'timeoutMs', { enumerable: true, get() { throw new Error('getter'); } });
  assert.throws(() => createProtectedResourceTransport(accessor), TypeError);
  const transport = createProtectedResourceTransport(valid);
  for (const value of [
    artifact(h, { body: '{"x":1,"x":2}' }), artifact(h, { method: 'GET' }), artifact(h, { url: `${h.origin}/other` }),
    artifact(h, { authorization: 'Bearer token' }), artifact(h, { dpop: 'not-a-jws' }), artifact(h, { body: '[]' }),
    artifact(h, { body: encoder.encode('{}') }),
    artifact(h, { body: '{"x":"' + 'a'.repeat(32768) + '"}' }),
  ]) await assert.rejects(transport.post(value, deadline()), invalid);
  await assert.rejects(transport.post(artifact(h), performance.now() - 1), invalid);
  await assert.rejects(transport.post(artifact(h), performance.now() + 121), invalid);
  assert.equal(calls, 0); await transport.close();
});

test('accepts the signer token maximum while rejecting longer token and DPoP bytes before I/O', async t => {
  let calls = 0;
  const h = await host((_req, res) => { calls += 1; json(res, 200, {}); }, { maxHeaderSize: 32 * 1024 }); t.after(h.close);
  const transport = createProtectedResourceTransport(configuration(h));
  const maxToken = `a.${'b'.repeat(16380)}.c`;
  await transport.post(artifact(h, { authorization: `DPoP ${maxToken}` }), deadline());
  assert.equal(calls, 1);
  await assert.rejects(transport.post(artifact(h, { authorization: `DPoP ${maxToken}x` }), deadline()), invalid);
  const overDpop = `a.${'b'.repeat(8189)}.c`;
  await assert.rejects(transport.post(artifact(h, { dpop: overDpop }), deadline()), invalid);
  assert.equal(calls, 1); await transport.close();
});

test('fails closed for foreign TLS, hostile framing and malformed JSON without retrying', async t => {
  let mode = 'duplicate-header'; let calls = 0;
  const h = await host((_req, res) => {
    calls += 1;
    if (mode === 'duplicate-header') { const bytes = Buffer.from('{}'); res.writeHead(401, ['content-type', 'application/json', 'content-type', 'application/json', 'content-length', String(bytes.length), 'cache-control', 'no-store']); return res.end(bytes); }
    if (mode === 'encoding') return json(res, 401, {}, { 'content-encoding': 'gzip' });
    if (mode === 'cookie') return json(res, 401, {}, { 'set-cookie': 'bad' });
    if (mode === 'redirect') return json(res, 302, {});
    if (mode === 'bad-json') { const bytes = Buffer.from('{"x":1,"x":2}'); res.writeHead(401, { 'content-type': 'application/json', 'content-length': String(bytes.length), 'cache-control': 'no-store' }); return res.end(bytes); }
    if (mode === 'malformed-then-close') { res.writeHead(401, { 'content-type': 'text/plain', 'content-length': '32', 'cache-control': 'no-store' }); res.flushHeaders(); return setTimeout(() => res.socket.destroy(), 10); }
    if (mode === 'delayed') return setTimeout(() => json(res, 401, {}), 80);
    if (mode === 'closed') return res.socket.destroy();
    throw new Error(`unknown ${mode}`);
  });
  t.after(h.close);
  const foreign = certificates(); t.after(() => rmSync(foreign.dir, { recursive: true, force: true }));
  const foreignTransport = createProtectedResourceTransport(configuration(h, { tls: { ca: foreign.ca } }));
  await assert.rejects(foreignTransport.post(artifact(h), deadline()), unavailable); assert.equal(calls, 0); await foreignTransport.close();
  const transport = createProtectedResourceTransport(configuration(h));
  for (const current of ['duplicate-header', 'encoding', 'cookie', 'redirect', 'bad-json', 'malformed-then-close', 'closed']) {
    mode = current; await assert.rejects(transport.post(artifact(h), deadline()), unavailable, current);
  }
  mode = 'delayed'; await assert.rejects(transport.post(artifact(h), deadline(10)), unavailable); await delay(100);
  assert.equal(calls, 8); await transport.close();
});

test('holds capacity through socket close and fences late success at the absolute deadline', async t => {
  let entered; let calls = 0;
  const h = await host((_req, res) => { calls += 1; if (entered) entered(); else json(res, 200, { accepted: true }); }); t.after(h.close);
  const transport = createProtectedResourceTransport(configuration(h, { timeoutMs: 200, maxConcurrent: 1 }));
  const first = await transport.post(artifact(h), deadline()); assert.equal(first.status, 200);
  const started = new Promise(resolve => { entered = resolve; });
  const pending = transport.post(artifact(h), deadline(180)); await started;
  await assert.rejects(transport.post(artifact(h), deadline(80)), unavailable);
  const closed = transport.close(); await assert.rejects(pending, unavailable); await closed;
  assert.equal(calls, 2); await assert.rejects(transport.post(artifact(h), deadline()), unavailable);
});

test('does not settle an observed response after a blocked close crosses its deadline', async t => {
  const h = await host((_req, res) => json(res, 200, { accepted: true })); t.after(h.close);
  const transport = createProtectedResourceTransport(configuration(h, { timeoutMs: 1000 }));
  const original = https.request; const end = deadline(300); let injected = 0;
  https.request = function (...args) {
    const request = original.apply(this, args);
    request.prependOnceListener('close', () => { injected += 1; while (performance.now() < end + 5) { /* host-close fault */ } });
    return request;
  };
  try {
    await assert.rejects(transport.post(artifact(h), end), unavailable); assert.equal(injected, 1);
  } finally { https.request = original; await transport.close(); }
});

test('close after response headers are observed fences the pending result and future calls', async t => {
  let observed;
  const h = await host((_req, res) => { res.writeHead(200, { 'content-type': 'application/json', 'content-length': '17', 'cache-control': 'no-store' }); res.flushHeaders(); observed(); });
  t.after(h.close);
  const transport = createProtectedResourceTransport(configuration(h, { timeoutMs: 500 }));
  const response = new Promise(resolve => { observed = resolve; });
  const pending = transport.post(artifact(h), deadline(400));
  await response;
  await transport.close();
  await assert.rejects(pending, unavailable);
  await assert.rejects(transport.post(artifact(h), deadline()), unavailable);
});
