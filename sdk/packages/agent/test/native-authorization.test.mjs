import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';

import { createNativeAuthorizationTransport } from '../src/native-authorization.mjs';

const encoder = new TextEncoder();
const dpop = 'eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiJ0ZXN0In0.signature';

function openssl(dir, ...args) { execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' }); }
function certificates() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'atum-agent-native-transport-'));
  writeFileSync(path.join(dir, 'server.ext'), 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n');
  openssl(dir, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-subj', '/CN=atum-agent-native-test-ca');
  openssl(dir, 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'server.key', '-out', 'server.csr', '-subj', '/CN=localhost');
  openssl(dir, 'x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'server.pem', '-days', '1', '-extfile', 'server.ext');
  return { dir, ca: readFileSync(path.join(dir, 'ca.pem'), 'utf8'), cert: readFileSync(path.join(dir, 'server.pem')), key: readFileSync(path.join(dir, 'server.key')) };
}
async function host(handler) {
  const certs = certificates();
  const server = https.createServer({ cert: certs.cert, key: certs.key }, handler);
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const origin = 'https://localhost:' + server.address().port;
  return { certs, origin, close: async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    rmSync(certs.dir, { recursive: true, force: true });
  } };
}
function configuration(h, changes = {}) {
  return { endpoints: { par_url: h.origin + '/request', device_authorization_url: h.origin + '/device/auth' },
    tls: { ca: h.certs.ca }, timeoutMs: 80, maxConcurrent: 1, ...changes };
}
function writeJson(res, status, value, extra = {}) {
  const body = Buffer.from(JSON.stringify(value));
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': String(body.length), 'cache-control': 'no-store', ...extra });
  res.end(body);
}
function deadline(milliseconds = 60) { return performance.now() + milliseconds; }
function unavailable(error) { return error instanceof Error && error.message === 'temporarily_unavailable'; }

test('a successful native response cannot resolve after its original deadline at request close', async t => {
  let httpRequests = 0; let injected = 0;
  const h = await host((_req, res) => { httpRequests += 1; writeJson(res, 201, { request_uri: 'fixture', expires_in: 60 }); });
  t.after(h.close);
  const transport = createNativeAuthorizationTransport(configuration(h, { timeoutMs: 1000 }));
  const original = https.request;
  const end = deadline(500);
  https.request = function (...args) {
    const request = original.apply(this, args);
    request.prependOnceListener('close', () => {
      injected += 1;
      // A host callback can block timers after response end, before final settlement.
      while (performance.now() < end + 5) { /* deterministic event-loop fault */ }
    });
    return request;
  };
  try {
    await assert.rejects(transport.postForm('par', encoder.encode('client_id=client'), dpop, end), unavailable);
    assert.equal(httpRequests, 1); assert.equal(injected, 1);
  } finally { https.request = original; await transport.close(); }
});

test('posts an immutable form snapshot with exactly one DPoP header to configured PAR and Device endpoints', async t => {
  const seen = [];
  const h = await host(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    seen.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString('utf8') });
    writeJson(res, req.url === '/request' ? 201 : 400, { nested: { response: true }, values: [1, 2] });
  });
  t.after(h.close);
  const transport = createNativeAuthorizationTransport(configuration(h));
  let speciesCalls = 0;
  class HostileBytes extends Uint8Array {
    static get [Symbol.species]() { speciesCalls += 1; throw new Error('species must not run'); }
  }
  const form = new HostileBytes(encoder.encode('client_id=client&scope=openid'));
  const pending = transport.postForm('par', form, dpop, deadline()); form.fill(0);
  const par = await pending;
  const device = await transport.postForm('device', encoder.encode('client_id=client'), dpop, deadline());
  assert.equal(par.status, 201); assert.equal(device.status, 400);
  assert.deepEqual(par.body, { nested: { response: true }, values: [1, 2] });
  assert.equal(Object.isFrozen(par), true); assert.equal(Object.isFrozen(par.body), true);
  assert.equal(Object.isFrozen(par.body.nested), true); assert.equal(Object.isFrozen(par.body.values), true);
  assert.throws(() => { par.body.nested.response = false; }, TypeError);
  assert.equal(speciesCalls, 0);
  assert.deepEqual(seen.map(item => [item.method, item.url, item.body]), [['POST', '/request', 'client_id=client&scope=openid'], ['POST', '/device/auth', 'client_id=client']]);
  for (const item of seen) {
    assert.equal(item.headers['content-type'], 'application/x-www-form-urlencoded');
    assert.equal(item.headers['content-length'], String(Buffer.byteLength(item.body)));
    assert.equal(item.headers.dpop, dpop); assert.equal(item.headers['dpop-nonce'], undefined);
    assert.equal(item.headers.accept, 'application/json'); assert.equal(item.headers['cache-control'], 'no-store'); assert.equal(item.headers.connection, 'close');
    assert.equal(item.headers.authorization, undefined); assert.equal(item.headers.cookie, undefined); assert.equal(item.headers['proxy-authorization'], undefined);
  }
  await transport.close();
});

test('rejects malformed configuration, input and deadlines before native authorization network I/O', async t => {
  let calls = 0;
  const h = await host((_req, res) => { calls += 1; writeJson(res, 201, {}); }); t.after(h.close);
  const valid = configuration(h);
  const invalid = [
    { ...valid, endpoints: { ...valid.endpoints, extra: h.origin + '/extra' } },
    { ...valid, endpoints: { par_url: 'http://' + h.origin.slice('https://'.length) + '/request', device_authorization_url: valid.endpoints.device_authorization_url } },
    { ...valid, endpoints: { par_url: h.origin + '/request?x=1', device_authorization_url: valid.endpoints.device_authorization_url } },
    { ...valid, endpoints: { par_url: valid.endpoints.par_url, device_authorization_url: 'https://other.example/device/auth' } },
    { ...valid, tls: { ca: valid.tls.ca, extra: true } },
    { ...valid, tls: { ca: 'not a PEM certificate' } },
    { ...valid, tls: { ca: h.certs.cert.toString('utf8') } },
    { ...valid, timeoutMs: 0 }, { ...valid, timeoutMs: 5001 }, { ...valid, maxConcurrent: 17 },
  ];
  for (const value of invalid) assert.throws(() => createNativeAuthorizationTransport(value), TypeError);
  const systemTrust = createNativeAuthorizationTransport(configuration(h, { tls: {} }));
  await systemTrust.close();
  const accessor = configuration(h);
  Object.defineProperty(accessor, 'timeoutMs', { enumerable: true, get() { throw new Error('must not run accessor'); } });
  assert.throws(() => createNativeAuthorizationTransport(accessor), TypeError);
  const transport = createNativeAuthorizationTransport(valid);
  await assert.rejects(transport.postForm('unknown', encoder.encode('x=1'), dpop, deadline()), TypeError);
  await assert.rejects(transport.postForm('par', 'x=1', dpop, deadline()), TypeError);
  await assert.rejects(transport.postForm('par', new Uint8Array(16385), dpop, deadline()), TypeError);
  await assert.rejects(transport.postForm('par', encoder.encode('x=1'), 'not-a-compact-jws', deadline()), TypeError);
  await assert.rejects(transport.postForm('par', encoder.encode('x=1'), dpop, performance.now() + 81), TypeError);
  await assert.rejects(transport.postForm('par', encoder.encode('x=1'), dpop, performance.now() - 1), TypeError);
  assert.equal(calls, 0); await transport.close();

  const mutable = configuration(h);
  const snapshotted = createNativeAuthorizationTransport(mutable);
  mutable.endpoints.par_url = h.origin + '/different';
  await snapshotted.postForm('par', encoder.encode('x=1'), dpop, deadline());
  assert.equal(calls, 1);
  await snapshotted.close();
});

test('a syntactically valid foreign CA fails the native authorization TLS handshake before HTTP', async t => {
  let calls = 0;
  const h = await host((_req, res) => { calls += 1; writeJson(res, 201, {}); }); t.after(h.close);
  const foreign = certificates(); t.after(() => rmSync(foreign.dir, { recursive: true, force: true }));
  const transport = createNativeAuthorizationTransport(configuration(h, { tls: { ca: foreign.ca } }));
  await assert.rejects(transport.postForm('par', encoder.encode('x=1'), dpop, deadline()), unavailable);
  assert.equal(calls, 0); await transport.close();
});

test('fails closed on hostile native authorization framing, strict JSON, delay, truncation and connection closure without retries', async t => {
  let mode = 'content-type'; let calls = 0;
  const h = await host((_req, res) => {
    calls += 1;
    if (mode === 'redirect') return writeJson(res, 302, {});
    if (mode === 'encoding') return writeJson(res, 201, {}, { 'content-encoding': 'gzip' });
    if (mode === 'cookie') return writeJson(res, 201, {}, { 'set-cookie': 'session=bad' });
    if (mode === 'content-type') return writeJson(res, 201, {}, { 'content-type': 'text/plain' });
    if (mode === 'duplicate-header') {
      const bytes = Buffer.from('{}');
      res.writeHead(201, ['content-type', 'application/json', 'content-type', 'application/json', 'content-length', String(bytes.length), 'cache-control', 'no-store']);
      return res.end(bytes);
    }
    if (mode === 'duplicate-json') {
      const bytes = Buffer.from('{"x":1,"x":2}');
      res.writeHead(201, { 'content-type': 'application/json', 'content-length': String(bytes.length), 'cache-control': 'no-store' }); return res.end(bytes);
    }
    if (mode === 'fraction') {
      const bytes = Buffer.from('{"x":1.5}');
      res.writeHead(201, { 'content-type': 'application/json', 'content-length': String(bytes.length), 'cache-control': 'no-store' }); return res.end(bytes);
    }
    if (mode === 'invalid-utf8') {
      const bytes = Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0xc3, 0x28, 0x7d]);
      res.writeHead(201, { 'content-type': 'application/json', 'content-length': String(bytes.length), 'cache-control': 'no-store' }); return res.end(bytes);
    }
    if (mode === 'oversized') {
      const bytes = Buffer.from('{"x":"' + 'a'.repeat(32761) + '"}');
      res.writeHead(201, { 'content-type': 'application/json', 'content-length': String(bytes.length), 'cache-control': 'no-store' }); return res.end(bytes);
    }
    if (mode === 'truncated') {
      res.writeHead(201, { 'content-type': 'application/json', 'content-length': '8', 'cache-control': 'no-store' }); res.write('{"x"'); return res.socket.destroy();
    }
    if (mode === 'delayed') return setTimeout(() => writeJson(res, 201, {}), 80);
    if (mode === 'close') return res.socket.destroy();
    throw new Error('unknown mode ' + mode);
  });
  t.after(h.close);
  const transport = createNativeAuthorizationTransport(configuration(h, { timeoutMs: 100 }));
  for (const current of ['content-type', 'redirect', 'encoding', 'cookie', 'duplicate-header', 'duplicate-json', 'fraction', 'invalid-utf8', 'oversized', 'truncated', 'close']) {
    mode = current;
    await assert.rejects(transport.postForm('par', encoder.encode('x=1'), dpop, deadline()), unavailable, current);
  }
  mode = 'delayed';
  await assert.rejects(transport.postForm('par', encoder.encode('x=1'), dpop, deadline(10)), unavailable);
  await delay(100);
  assert.equal(calls, 12); await transport.close();
});

test('capacity is held for a native request until the socket closes and close fences pending and later work', async t => {
  let entered;
  const h = await host((_req, _res) => { entered(); }); t.after(h.close);
  const transport = createNativeAuthorizationTransport(configuration(h, { timeoutMs: 200, maxConcurrent: 1 }));
  const started = new Promise(resolve => { entered = resolve; });
  const first = transport.postForm('par', encoder.encode('x=1'), dpop, deadline(180));
  await started;
  await assert.rejects(transport.postForm('device', encoder.encode('x=1'), dpop, deadline(100)), unavailable);
  const closed = transport.close();
  await assert.rejects(first, unavailable);
  await closed;
  await assert.rejects(transport.postForm('par', encoder.encode('x=1'), dpop, deadline()), unavailable);
});
