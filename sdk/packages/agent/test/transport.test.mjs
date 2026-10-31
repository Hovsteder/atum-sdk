import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';

import { createRequestTransport } from '../src/transport.mjs';

const encoder = new TextEncoder();

function openssl(dir, ...args) { execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' }); }
function certificates() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'atum-agent-transport-'));
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
  const origin = 'https://localhost:' + server.address().port;
  return { certs, origin, close: async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    rmSync(certs.dir, { recursive: true, force: true });
  } };
}
function configuration(h, changes = {}) {
  return { endpoints: { options_url: h.origin + '/atum/request/options', verify_url: h.origin + '/atum/request/verify' },
    tls: { ca: h.certs.ca }, timeoutMs: 80, maxConcurrent: 1, ...changes };
}
function writeJson(res, status, value, extra = {}) {
  const body = Buffer.from(JSON.stringify(value));
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': String(body.length), 'cache-control': 'no-store', ...extra });
  res.end(body);
}
function deadline(milliseconds = 60) { return performance.now() + milliseconds; }
function unavailable(error) { return error instanceof Error && error.message === 'temporarily_unavailable'; }

test('posts only configured routes over trusted TLS and returns deeply frozen JSON for 200 and known non-200', async t => {
  const seen = [];
  const h = await host(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    seen.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString('utf8') });
    writeJson(res, req.url.endsWith('/options') ? 200 : 409, { nested: { response: true }, values: [1, 2] });
  });
  t.after(h.close);
  const transport = createRequestTransport(configuration(h));
  let speciesCalls = 0;
  class HostileBytes extends Uint8Array {
    static get [Symbol.species]() { speciesCalls += 1; throw new Error('species must not run'); }
  }
  const body = new HostileBytes(encoder.encode('{"request":1}'));
  const pending = transport.postJson('options', body, deadline()); body.fill(0);
  const success = await pending;
  const conflict = await transport.postJson('verify', encoder.encode('{"proof":1}'), deadline());
  assert.equal(success.status, 200); assert.equal(conflict.status, 409);
  assert.deepEqual(success.body, { nested: { response: true }, values: [1, 2] });
  assert.equal(Object.isFrozen(success), true); assert.equal(Object.isFrozen(success.body), true);
  assert.equal(Object.isFrozen(success.body.nested), true); assert.equal(Object.isFrozen(success.body.values), true);
  assert.throws(() => { success.body.nested.response = false; }, TypeError);
  assert.equal(speciesCalls, 0);
  assert.deepEqual(seen.map(item => [item.method, item.url, item.body]), [['POST', '/atum/request/options', '{"request":1}'], ['POST', '/atum/request/verify', '{"proof":1}']]);
  for (const item of seen) {
    assert.equal(item.headers['content-type'], 'application/json');
    assert.equal(item.headers['content-length'], String(Buffer.byteLength(item.body)));
    assert.equal(item.headers.authorization, undefined); assert.equal(item.headers.cookie, undefined); assert.equal(item.headers['proxy-authorization'], undefined);
  }
  await transport.close();
});

test('rejects malformed configuration, routes, bytes and deadlines before network I/O', async t => {
  let calls = 0;
  const h = await host((_req, res) => { calls += 1; writeJson(res, 200, {}); }); t.after(h.close);
  const valid = configuration(h);
  const invalid = [
    { ...valid, endpoints: { ...valid.endpoints, extra: h.origin + '/extra' } },
    { ...valid, endpoints: { options_url: 'http://' + h.origin.slice('https://'.length) + '/options', verify_url: valid.endpoints.verify_url } },
    { ...valid, endpoints: { options_url: h.origin + '/options?x=1', verify_url: valid.endpoints.verify_url } },
    { ...valid, endpoints: { options_url: valid.endpoints.options_url, verify_url: 'https://other.example/verify' } },
    { ...valid, tls: { ca: valid.tls.ca, extra: true } },
    { ...valid, tls: { ca: 'not a PEM certificate' } },
    { ...valid, tls: { ca: '-----BEGIN CERTIFICATE-----\ntruncated\n-----END CERTIFICATE-----\n' } },
    { ...valid, tls: { ca: h.certs.cert.toString('utf8') } },
    { ...valid, timeoutMs: 0 }, { ...valid, maxConcurrent: 17 },
  ];
  for (const value of invalid) assert.throws(() => createRequestTransport(value), TypeError);
  const transport = createRequestTransport(valid);
  await assert.rejects(transport.postJson('unknown', encoder.encode('{}'), deadline()), TypeError);
  await assert.rejects(transport.postJson('options', '{}', deadline()), TypeError);
  await assert.rejects(transport.postJson('options', new Uint8Array(32769), deadline()), TypeError);
  await assert.rejects(transport.postJson('options', encoder.encode('{}'), performance.now() + 81), TypeError);
  await assert.rejects(transport.postJson('options', encoder.encode('{}'), performance.now() - 1), TypeError);
  assert.equal(calls, 0); await transport.close();
});

test('a syntactically valid foreign CA fails the real TLS handshake before HTTP', async t => {
  let calls = 0;
  const h = await host((_req, res) => { calls += 1; writeJson(res, 200, {}); }); t.after(h.close);
  const foreign = certificates(); t.after(() => rmSync(foreign.dir, { recursive: true, force: true }));
  const transport = createRequestTransport(configuration(h, { tls: { ca: foreign.ca } }));
  await assert.rejects(transport.postJson('options', encoder.encode('{}'), deadline()), unavailable);
  assert.equal(calls, 0);
  await transport.close();
});

test('fails closed on hostile framing, strict JSON, delay, truncation and connection closure without retrying', async t => {
  let mode = 'content-type'; let calls = 0;
  const h = await host((_req, res) => {
    calls += 1;
    if (mode === 'redirect') return writeJson(res, 302, {});
    if (mode === 'encoding') return writeJson(res, 200, {}, { 'content-encoding': 'gzip' });
    if (mode === 'cookie') return writeJson(res, 200, {}, { 'set-cookie': 'session=bad' });
    if (mode === 'content-type') return writeJson(res, 200, {}, { 'content-type': 'text/plain' });
    if (mode === 'duplicate-header') {
      const bytes = Buffer.from('{}');
      res.writeHead(200, ['content-type', 'application/json', 'content-type', 'application/json', 'content-length', String(bytes.length), 'cache-control', 'no-store']);
      return res.end(bytes);
    }
    if (mode === 'duplicate-json') {
      const bytes = Buffer.from('{"x":1,"x":2}');
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(bytes.length), 'cache-control': 'no-store' }); return res.end(bytes);
    }
    if (mode === 'fraction') {
      const bytes = Buffer.from('{"x":1.5}');
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(bytes.length), 'cache-control': 'no-store' }); return res.end(bytes);
    }
    if (mode === 'invalid-utf8') {
      const bytes = Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0xc3, 0x28, 0x7d]);
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(bytes.length), 'cache-control': 'no-store' }); return res.end(bytes);
    }
    if (mode === 'oversized') {
      const bytes = Buffer.from('{"x":"' + 'a'.repeat(32761) + '"}');
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(bytes.length), 'cache-control': 'no-store' }); return res.end(bytes);
    }
    if (mode === 'truncated') {
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': '8', 'cache-control': 'no-store' }); res.write('{"x"'); return res.socket.destroy();
    }
    if (mode === 'delayed') return setTimeout(() => writeJson(res, 200, {}), 80);
    if (mode === 'close') return res.socket.destroy();
    throw new Error('unknown mode ' + mode);
  });
  t.after(h.close);
  const transport = createRequestTransport(configuration(h, { timeoutMs: 100 }));
  for (const current of ['content-type', 'redirect', 'encoding', 'cookie', 'duplicate-header', 'duplicate-json', 'fraction', 'invalid-utf8', 'oversized', 'truncated', 'close']) {
    mode = current;
    await assert.rejects(transport.postJson('options', encoder.encode('{}'), deadline()), unavailable, current);
  }
  mode = 'delayed';
  await assert.rejects(transport.postJson('options', encoder.encode('{}'), deadline(10)), unavailable);
  await delay(100);
  assert.equal(calls, 12); await transport.close();
});

test('capacity is held for active work and close destroys it before rejecting future calls', async t => {
  let entered;
  const h = await host((_req, _res) => { entered(); }); t.after(h.close);
  const transport = createRequestTransport(configuration(h, { timeoutMs: 200, maxConcurrent: 1 }));
  const started = new Promise(resolve => { entered = resolve; });
  const first = transport.postJson('options', encoder.encode('{}'), deadline(180));
  await started;
  await assert.rejects(transport.postJson('verify', encoder.encode('{}'), deadline(100)), unavailable);
  const closed = transport.close();
  await assert.rejects(first, unavailable);
  await closed;
  await assert.rejects(transport.postJson('options', encoder.encode('{}'), deadline()), unavailable);
});
