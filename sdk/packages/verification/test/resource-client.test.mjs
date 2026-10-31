import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createResourceClient, ResourceTransportError } from '../src/resource-client.mjs';

const fixture = JSON.parse(readFileSync(path.join(import.meta.dirname, 'fixtures/proof-vectors.json')));
const bound = JSON.parse(fixture.cases[0].input.body);
const baseInput = { ...bound, client_id: 'client.resource' };

function openssl(dir, ...args) { execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' }); }
function certificates() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'atum-resource-client-'));
  writeFileSync(path.join(dir, 'server.ext'), 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n');
  writeFileSync(path.join(dir, 'client.ext'), 'extendedKeyUsage=clientAuth\n');
  openssl(dir, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-subj', '/CN=atum-test-ca');
  openssl(dir, 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'server.key', '-out', 'server.csr', '-subj', '/CN=localhost');
  openssl(dir, 'x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'server.pem', '-days', '1', '-extfile', 'server.ext');
  openssl(dir, 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'client.key', '-out', 'client.csr', '-subj', '/CN=atum-client');
  openssl(dir, 'x509', '-req', '-in', 'client.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'client.pem', '-days', '1', '-extfile', 'client.ext');
  return { dir, ca: readFileSync(path.join(dir, 'ca.pem'), 'utf8'), cert: readFileSync(path.join(dir, 'client.pem'), 'utf8'), key: readFileSync(path.join(dir, 'client.key'), 'utf8'), serverCert: readFileSync(path.join(dir, 'server.pem')), serverKey: readFileSync(path.join(dir, 'server.key')) };
}

async function host(handler, { mtls = true } = {}) {
  const certs = certificates();
  const server = https.createServer({ cert: certs.serverCert, key: certs.serverKey,
    ...(mtls ? { ca: certs.ca, requestCert: true, rejectUnauthorized: true } : {}) }, handler);
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  return { certs, url: `https://localhost:${port}`, close: async () => { await new Promise(resolve => server.close(resolve)); rmSync(certs.dir, { recursive: true, force: true }); } };
}
function respond(res, status, body, headers = {}) { const bytes = Buffer.from(body); res.writeHead(status, { 'content-type': 'application/json', 'content-length': String(bytes.length), 'cache-control': 'no-store', ...headers }); res.end(bytes); }
function config(h, extra = {}) { return { baseUrl: h.url, registration: fixture.registration, tls: { ca: h.certs.ca, cert: h.certs.cert, key: h.certs.key }, timeoutMs: 500, maxConcurrent: 1, ...extra }; }
function expectCode(code) { return error => error instanceof ResourceTransportError && error.code === code; }

test('resource client uses mTLS, binds exact routes, and snapshots input', async (t) => {
  let seen = 0;
  const h = await host((req, res) => {
    seen += 1;
    assert.equal(req.socket.authorized, true);
    assert.equal(req.method, 'POST'); assert.equal(req.url, '/v1/authority/grant-snapshot');
    let text = ''; req.setEncoding('utf8'); req.on('data', chunk => { text += chunk; }); req.on('end', () => {
      const body = JSON.parse(text); assert.equal(body.client_id, 'client.resource');
      respond(res, 200, JSON.stringify({ assertion: 'a.b.c' }));
    });
  });
  t.after(h.close);
  const client = createResourceClient(config(h));
  const input = structuredClone(baseInput); const pending = client.snapshot(input);
  input.client_id = 'changed'; input.context.tenant_id = 'changed';
  assert.equal(await pending, 'a.b.c'); assert.equal(seen, 1);
  await client.close();
});

test('service credential uses the separate HTTPS authority routes without a client certificate', async (t) => {
  const credential = `atum_svc_${Buffer.alloc(32, 7).toString('base64url')}`;
  const h = await host((req, res) => {
    assert.equal(req.socket.authorized, false);
    assert.equal(req.headers.authorization, `Bearer ${credential}`);
    assert.equal(req.url, '/v1/service/authority/grant-snapshot');
    req.resume(); req.on('end', () => respond(res, 200, JSON.stringify({ assertion: 'a.b.c' })));
  }, { mtls: false });
  t.after(h.close);
  const client = createResourceClient({ baseUrl: h.url, registration: fixture.registration,
    https: { ca: h.certs.ca }, serviceCredential: credential, timeoutMs: 500, maxConcurrent: 1 });
  assert.equal(await client.snapshot(baseInput), 'a.b.c');
  await client.close();
});

test('only the exact authenticated 404/not_found pair is authoritative', async (t) => {
  const h = await host((_req, res) => respond(res, 404, JSON.stringify({ error: { code: 'not_found' } })));
  t.after(h.close);
  const client = createResourceClient(config(h));
  await assert.rejects(client.retrieve(baseInput), expectCode('not_found'));
  await client.close();
  const bad = await host((_req, res) => { res.writeHead(404, { 'content-type': 'text/html', 'content-length': '9' }); res.end('not found'); });
  t.after(bad.close);
  const badClient = createResourceClient(config(bad));
  await assert.rejects(badClient.retrieve(baseInput), expectCode('temporarily_unavailable'));
  await badClient.close();
});

test('rejects redirects, malformed responses, slow responses, excess calls, and calls after close', async (t) => {
  const h = await host((_req, res) => setTimeout(() => respond(res, 302, JSON.stringify({ assertion: 'a.b.c' }), { location: '/elsewhere' }), 80));
  t.after(h.close);
  const client = createResourceClient(config(h, { timeoutMs: 30 }));
  const first = client.snapshot(baseInput);
  await assert.rejects(client.admit(baseInput), expectCode('temporarily_unavailable'));
  await assert.rejects(first, expectCode('temporarily_unavailable'));
  await client.close();
  await assert.rejects(client.retrieve(baseInput), expectCode('temporarily_unavailable'));
});

test('rejects input before network and requires client identity', async (t) => {
  const h = await host(() => assert.fail('invalid payload made network request'));
  t.after(h.close);
  const client = createResourceClient(config(h));
  await assert.rejects(client.snapshot({ ...baseInput, client_id: '' }), expectCode('invalid_request'));
  await assert.rejects(client.snapshot({ ...baseInput, context: { ...baseInput.context, tenant_id: 'foreign' } }), expectCode('invalid_request'));
  await client.close();
});

test('keeps hostname verification and strict JSON response parsing enabled', async (t) => {
  const h = await host((_req, res) => {
    const body = '{"assertion":"a.b.c","assertion":"d.e.f"}';
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), 'cache-control': 'no-store' });
    res.end(body);
  });
  t.after(h.close);
  const duplicate = createResourceClient(config(h));
  await assert.rejects(duplicate.snapshot(baseInput), expectCode('temporarily_unavailable'));
  await duplicate.close();
  const port = new URL(h.url).port;
  const wrongName = createResourceClient(config(h, { baseUrl: `https://127.0.0.1:${port}` }));
  await assert.rejects(wrongName.snapshot(baseInput), expectCode('temporarily_unavailable'));
  await wrongName.close();
});

test('does not accept a foreign CA or client certificate', async (t) => {
  const h = await host((_req, res) => respond(res, 200, JSON.stringify({ assertion: 'a.b.c' })));
  const foreign = certificates();
  t.after(h.close); t.after(() => rmSync(foreign.dir, { recursive: true, force: true }));
  const wrongCa = createResourceClient(config(h, { tls: { ca: foreign.ca, cert: h.certs.cert, key: h.certs.key } }));
  await assert.rejects(wrongCa.snapshot(baseInput), expectCode('temporarily_unavailable'));
  await wrongCa.close();
  const wrongClient = createResourceClient(config(h, { tls: { ca: h.certs.ca, cert: foreign.cert, key: foreign.key } }));
  await assert.rejects(wrongClient.snapshot(baseInput), expectCode('temporarily_unavailable'));
  await wrongClient.close();
});

test('rejects chunked and oversized protocol replies', async (t) => {
  let mode = 'chunked';
  const h = await host((_req, res) => {
    if (mode === 'chunked') { res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end('{"assertion":"a.b.c"}'); return; }
    const body = Buffer.alloc(65537, 0x61); res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(body.length), 'cache-control': 'no-store' }); res.end(body);
  });
  t.after(h.close);
  const client = createResourceClient(config(h));
  await assert.rejects(client.snapshot(baseInput), expectCode('temporarily_unavailable'));
  mode = 'oversize';
  await assert.rejects(client.snapshot(baseInput), expectCode('temporarily_unavailable'));
  await client.close();
});


test('invalid local TLS material fails safely without a leaked timer', () => {
  const source = `
    import assert from 'node:assert/strict';
    import { readFileSync } from 'node:fs';
    import { createResourceClient, ResourceTransportError } from ${JSON.stringify(new URL('../src/resource-client.mjs', import.meta.url).href)};
    const fixture = JSON.parse(readFileSync(new URL(${JSON.stringify(new URL('fixtures/proof-vectors.json', import.meta.url).href)})));
    const input = { ...JSON.parse(fixture.cases[0].input.body), client_id: 'client.resource' };
    let client;
    try {
      client = createResourceClient({ baseUrl: 'https://localhost:1', registration: fixture.registration,
        tls: { ca: 'invalid', cert: 'invalid', key: 'invalid' }, timeoutMs: 20, maxConcurrent: 1 });
    } catch (error) {
      assert.equal(error instanceof TypeError, true);
      assert.equal(error.message, 'invalid config');
    }
    if (client) {
      for (let i = 0; i < 2; i += 1) await assert.rejects(client.snapshot(input),
        error => error instanceof ResourceTransportError && error.code === 'temporarily_unavailable');
      await client.close();
    }
    await new Promise(resolve => setTimeout(resolve, 50));
    console.log('SAFE_TLS_FAILURE');
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', source], { encoding: 'utf8', timeout: 2000 });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /SAFE_TLS_FAILURE/);
});

test('synchronous request construction failures are safe and release their slot', async (t) => {
  const certs = certificates();
  t.after(() => rmSync(certs.dir, { recursive: true, force: true }));
  const client = createResourceClient({ baseUrl: 'https://localhost:1', registration: fixture.registration,
    tls: { ca: certs.ca, cert: certs.cert, key: certs.key }, timeoutMs: 20, maxConcurrent: 1 });
  const originalRequest = https.request;
  https.request = () => { throw new Error('construction failed'); };
  try {
    await assert.rejects(client.snapshot(baseInput), expectCode('temporarily_unavailable'));
    await assert.rejects(client.retrieve(baseInput), expectCode('temporarily_unavailable'));
    await client.close();
    await new Promise(resolve => setTimeout(resolve, 50));
  } finally {
    https.request = originalRequest;
  }
});

test('rejects URL-normalizing origins and coerced registration identities', async (t) => {
  const h = await host((_req, res) => respond(res, 200, JSON.stringify({ assertion: 'a.b.c' })));
  t.after(h.close);
  const malformedOrigins = [
    `${h.url}/v1/..`, `${h.url}?`, `${h.url}#`, `${h.url} `, h.url.replace('https://', 'https:\\\\'),
  ];
  for (const baseUrl of malformedOrigins) {
    assert.throws(() => createResourceClient(config(h, { baseUrl })), /invalid config/);
  }
  for (const field of ['issuer', 'audience']) {
    const registration = structuredClone(fixture.registration);
    registration[field] = 123;
    assert.throws(() => createResourceClient(config(h, { registration })), /invalid config/);
  }
});

test('deadline holds capacity until the TLS socket closes and close cancels its queued follow-up', async (t) => {
  const received = [];
  let firstRequest;
  let socketClosed;
  const firstArrived = new Promise(resolve => { firstRequest = resolve; });
  const firstSocketClosed = new Promise(resolve => { socketClosed = resolve; });
  const h = await host((req, res) => {
    received.push(req.url);
    if (req.url === '/v1/authority/grant-snapshot') {
      req.resume();
      req.socket.once('close', socketClosed);
      firstRequest();
      return;
    }
    respond(res, 200, JSON.stringify({ assertion: 'a.b.c' }));
  });
  t.after(h.close);
  const client = createResourceClient(config(h, { timeoutMs: 30 }));
  const first = client.snapshot(baseInput);
  await firstArrived;
  await assert.rejects(first, expectCode('temporarily_unavailable'));

  const second = client.retrieve(baseInput).then(
    value => ({ value }),
    error => ({ error }),
  );
  let closeResolved = false;
  const closing = client.close().then(() => { closeResolved = true; });
  await Promise.resolve();
  assert.equal(closeResolved, false, 'close resolved before the timed-out socket closed');
  await firstSocketClosed;
  await closing;
  assert.equal(expectCode('temporarily_unavailable')((await second).error), true);
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(received, ['/v1/authority/grant-snapshot']);
});
