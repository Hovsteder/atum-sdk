import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { PassThrough } from 'node:stream';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

import { intentHash } from '../src/context.mjs';
import { createCurrentAuthorizationVerifier, ResourceTransportError } from '../src/current-authorization.mjs';
import { createProtectedHttpHandler, ProtectedHttpError } from '../src/node-http.mjs';

const vectors = JSON.parse(readFileSync(new URL('fixtures/proof-vectors.json', import.meta.url)));
const protectedRequest = vectors.cases[0].input;
const requestBody = JSON.parse(protectedRequest.body);
const accessClaims = JSON.parse(Buffer.from(protectedRequest.authorization.split('.')[1], 'base64url'));
const clientId = accessClaims.client_id;
const now = vectors.clock.now_ms;

function openssl(dir, ...args) { execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' }); }
function certificates() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'atum-current-auth-'));
  writeFileSync(path.join(dir, 'server.ext'), 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n');
  writeFileSync(path.join(dir, 'client.ext'), 'extendedKeyUsage=clientAuth\n');
  openssl(dir, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-subj', '/CN=atum-test-ca');
  openssl(dir, 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'server.key', '-out', 'server.csr', '-subj', '/CN=localhost');
  openssl(dir, 'x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'server.pem', '-days', '1', '-extfile', 'server.ext');
  openssl(dir, 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'client.key', '-out', 'client.csr', '-subj', '/CN=atum-client');
  openssl(dir, 'x509', '-req', '-in', 'client.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'client.pem', '-days', '1', '-extfile', 'client.ext');
  return { dir, ca: readFileSync(path.join(dir, 'ca.pem'), 'utf8'), cert: readFileSync(path.join(dir, 'client.pem'), 'utf8'), key: readFileSync(path.join(dir, 'client.key'), 'utf8'), serverCert: readFileSync(path.join(dir, 'server.pem')), serverKey: readFileSync(path.join(dir, 'server.key')) };
}
function respond(res, body) { const bytes = Buffer.from(JSON.stringify(body)); res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(bytes.length), 'cache-control': 'no-store' }); res.end(bytes); }

async function host(mode = 'success') {
  const certs = certificates(); const authority = await generateKeyPair('ES256'); const publicJwk = await exportJWK(authority.publicKey);
  const paths = [];
  const sign = async (data, kind) => {
    const issued = kind === 'snapshot' ? data.issued_at_ms : data.evaluated_at_ms;
    const expires = kind === 'snapshot' ? data.valid_until_ms : data.first_submit_expires_at_ms;
    return new SignJWT({ iss: vectors.registration.issuer, aud: vectors.registration.audience,
      sub: requestBody.context.scoped_subject, iat: Math.floor(issued / 1000), exp: Math.ceil(expires / 1000),
      jti: kind === 'snapshot' ? 'snapshot-current-1' : data.admission_id,
      profile: kind === 'snapshot' ? 'atum-grant-status-v1-draft.1' : 'atum-admission-v1-draft.1', data })
      .setProtectedHeader({ alg: 'ES256', typ: kind === 'snapshot' ? 'atum-grant-status+jwt' : 'atum-admission+jwt', kid: 'authority-key' })
      .sign(authority.privateKey);
  };
  const server = https.createServer({ cert: certs.serverCert, key: certs.serverKey, ca: certs.ca, requestCert: true, rejectUnauthorized: true }, (req, res) => {
    paths.push(req.url); let text = ''; req.setEncoding('utf8'); req.on('data', chunk => { text += chunk; }); req.on('end', async () => {
      const input = JSON.parse(text); assert.deepEqual(input, { ...requestBody, client_id: clientId });
      if (req.url === '/v1/authority/grant-snapshot') {
        const template = Object.fromEntries(Object.entries(input.context).filter(([key]) => !['operation_id', 'action', 'action_hash'].includes(key)));
        const data = { grant: { template, client_id: clientId, grant_expires_at_ms: now + 100_000,
          grant_limit: 2, permissions: [{ action: 'sandbox.execute', max_amount: 1000, max_duration: 3600, max_price_sun: 1000 }] },
        status: 'active', evidence: null, issued_at_ms: now, valid_until_ms: now + 30_000 };
        respond(res, { assertion: await sign(data, 'snapshot') }); return;
      }
      assert.equal(req.url, '/v1/authority/admissions');
      if (mode === 'ambiguous') { req.socket.destroy(); return; }
      const data = { context: input.context, intent_hash: intentHash(input.context), admission_id: 'admission-current-1',
        decision: 'admitted', reason: 'admitted', evaluated_at_ms: now, evaluated_uncertainty_ms: 0,
        grant_expires_at_ms: now + 100_000, acceptance_expires_at_ms: now + 10_000,
        first_submit_expires_at_ms: now + 30_000, evidence: null };
      respond(res, { assertion: await sign(data, 'admission') });
    });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return { certs, publicJwk, paths, url: `https://localhost:${server.address().port}`,
    close: async () => { await new Promise(resolve => server.close(resolve)); rmSync(certs.dir, { recursive: true, force: true }); } };
}

async function verifier(h) {
  return createCurrentAuthorizationVerifier({ registration: vectors.registration, clock: () => vectors.clock,
    proof: { issuerKeys: vectors.issuer_keys, endpoint: vectors.endpoint, replayStore: { consume: async () => true } },
    authority: { issuerKeys: { 'authority-key': h.publicJwk }, evidencePolicy: null, baseUrl: h.url,
      tls: { ca: h.certs.ca, cert: h.certs.cert, key: h.certs.key }, timeoutMs: 500, maxConcurrent: 1 } });
}

function handlerConfig(h, onAuthorized = () => ({ ok: true }), extra = {}) {
  return { endpoint: vectors.endpoint, onAuthorized, ...extra, authorization: {
    registration: vectors.registration, clock: () => vectors.clock,
    proof: { issuerKeys: vectors.issuer_keys, endpoint: vectors.endpoint,
      replayStore: { consume: async () => true, issueNonce: async () => ({ nonce: 'fixture-nonce' }) } },
    authority: { issuerKeys: { 'authority-key': h.publicJwk }, evidencePolicy: null, baseUrl: h.url,
      tls: { ca: h.certs.ca, cert: h.certs.cert, key: h.certs.key }, timeoutMs: 500, maxConcurrent: 1 } } };
}
function message({ rawHeaders, body = protectedRequest.body, encrypted = true, pending = false } = {}) {
  const req = new PassThrough(); req.socket = { encrypted }; req.method = vectors.endpoint.method;
  req.url = new URL(vectors.endpoint.url).pathname;
  req.rawHeaders = rawHeaders ?? ['Host', new URL(vectors.endpoint.url).host, 'Authorization', protectedRequest.authorization,
    'DPoP', protectedRequest.dpop, 'Content-Type', 'application/json', 'Content-Length', String(Buffer.byteLength(body))];
  const res = { writeHead(status, headers) { this.status = status; this.headers = headers; }, end(bytes) { this.body = JSON.parse(bytes); } };
  if (!pending) req.end(body);
  return { req, res };
}

test('protected HTTP raw boundary, concurrent body timeout and drain preserve authority ordering', async t => {
  const h = await host(); t.after(h.close); let callbacks = 0;
  const resource = await createProtectedHttpHandler(handlerConfig(h, () => { callbacks++; return { ok: true }; },
    { maxConcurrent: 1, readTimeoutMs: 30 })); t.after(() => resource.close());
  const original = message().req.rawHeaders;
  for (const modify of [
    a => [...a, 'Host', new URL(vectors.endpoint.url).host],
    a => a.map((v, i) => i === 1 ? 'localhost:8443' : v),
    a => [...a, 'Transfer-Encoding', 'chunked'],
    a => [...a, 'Expect', '100-continue'],
    a => a.map((v, i) => i === 9 ? '01' : v),
  ]) {
    const { req, res } = message({ rawHeaders: modify(original) }); await resource.handle(req, res);
    assert.equal(res.status, 400); assert.equal(res.body.error.code, 'invalid_request'); req.destroy();
  }
  const insecure = message({ encrypted: false }); await resource.handle(insecure.req, insecure.res);
  assert.equal(insecure.res.status, 400); insecure.req.destroy();
  assert.equal(callbacks, 0); assert.deepEqual(h.paths, []);
  const stalled = message({ pending: true }); const pending = resource.handle(stalled.req, stalled.res);
  const excess = message(); await resource.handle(excess.req, excess.res);
  assert.equal(excess.res.status, 503); excess.req.destroy();
  const closing = resource.close(); assert.equal(closing, resource.close());
  await Promise.all([pending, closing]); assert.equal(stalled.req.destroyed, true);
  assert.deepEqual(h.paths, []); assert.equal(callbacks, 0);
});

test('protected HTTP invokes callback only after real signed authority and exposes only typed errors', async t => {
  const h = await host(); t.after(h.close); let mode = 'success'; let calls = 0;
  const resource = await createProtectedHttpHandler(handlerConfig(h, current => {
    calls++; assert.equal(current.authorization_effect, 'current_permission');
    if (mode === 'typed') throw new ProtectedHttpError('grant_not_active');
    if (mode === 'lookalike') throw Object.assign(new Error('private diagnostic'), { code: 'grant_not_active', name: 'UsageError' });
    return { permission_checked: true };
  })); t.after(() => resource.close());
  for (const [selected, status, code] of [['success',200,undefined],['typed',403,'grant_not_active'],['lookalike',503,'temporarily_unavailable']]) {
    mode = selected; const { req, res } = message(); await resource.handle(req, res);
    assert.equal(res.status, status); assert.equal(res.body.error?.code, code);
    assert.doesNotMatch(JSON.stringify(res.body), /private diagnostic/);
  }
  assert.equal(calls, 3); assert.equal(h.paths.length, 6);
});

test('fresh composition returns permission facts and preserves resource acceptance duty', async (t) => {
  const h = await host(); t.after(h.close); const current = await verifier(h); t.after(() => current.close());
  const result = await current.verifyCurrent(protectedRequest);
  assert.equal(result.authorization_effect, 'current_permission');
  assert.equal(result.requires_resource_acceptance, true);
  assert.equal(result.grant_limit, 2);
  assert.deepEqual(result.action_request, requestBody.action_request);
  assert.deepEqual(h.paths, ['/v1/authority/grant-snapshot', '/v1/authority/admissions']);
});

test('ambiguous admission is fenced without retrieve or resubmit', async (t) => {
  const h = await host('ambiguous'); t.after(h.close); const current = await verifier(h); t.after(() => current.close());
  await assert.rejects(current.verifyCurrent(protectedRequest), error => error instanceof ResourceTransportError && error.code === 'temporarily_unavailable');
  assert.deepEqual(h.paths, ['/v1/authority/grant-snapshot', '/v1/authority/admissions']);
});
