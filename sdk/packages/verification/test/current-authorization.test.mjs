import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

import { intentHash } from '../src/context.mjs';
import { createCurrentAuthorizationVerifier, ResourceTransportError } from '../src/current-authorization.mjs';

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
