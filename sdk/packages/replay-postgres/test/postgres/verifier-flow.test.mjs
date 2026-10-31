import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test, { after, before } from 'node:test';
import pg from 'pg';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createVerifier } from '@atum/verification';
import { intentHash } from '@atum/verification/context';
import { createPostgresReplayStore } from '../../src/store.mjs';
import { testConnection } from '../../tools/test-connection.mjs';

const base = JSON.parse(await readFile(new URL('../../../verification/test/fixtures/proof-vectors.json', import.meta.url)));
const issuer = await generateKeyPair('RS256', { modulusLength: 2048 });
const agent = await generateKeyPair('ES256');
const issuerJwk = { ...(await exportJWK(issuer.publicKey)), kid: 'integration-only', alg: 'RS256', use: 'sig' };
const agentJwk = await exportJWK(agent.publicKey);
const thumbprint = await calculateJwkThumbprint(agentJwk, 'sha256');
const now = base.clock.now_ms;
let pool;
before(() => { pool = new pg.Pool(testConnection()); });
after(async () => { await pool?.end(); });

async function flow(name, selectedPool = pool) {
  const body = JSON.parse(base.cases[0].input.body);
  body.context.issuer = `https://flow.issuer.invalid/${name}`;
  body.context.agent_key_thumbprint = thumbprint;
  const endpoint = base.endpoint;
  const registration = { ...base.registration, issuer: body.context.issuer,
    account_required_actions: ['prices.read', 'order.preview', 'sandbox.execute'] };
  const binding = { issuer: registration.issuer, audience: registration.audience, endpoint_url: endpoint.url };
  const clock = () => ({ now_ms: now, uncertainty_ms: 0, healthy: true });
  const store = createPostgresReplayStore({ pool: selectedPool, binding, clock });
  const verifier = await createVerifier({ registration, issuerKeys: [issuerJwk], endpoint, clock, replayStore: store });
  const oldToken = JSON.parse(Buffer.from(base.cases[0].input.authorization.split(' ')[1].split('.')[1], 'base64url'));
  const token = await new SignJWT({ ...oldToken, iss: registration.issuer, cnf: { jkt: thumbprint } })
    .setProtectedHeader({ typ: 'at+jwt', alg: 'RS256', kid: issuerJwk.kid }).sign(issuer.privateKey);
  async function request() {
    const issued = await store.issueNonce({ agent_key_thumbprint: thumbprint });
    const proof = await new SignJWT({ jti: randomBytes(16).toString('base64url'), htm: endpoint.method,
      htu: endpoint.url, iat: now / 1000, ath: createHash('sha256').update(token, 'ascii').digest('base64url'),
      nonce: issued.nonce, atum_intent_hash: intentHash(body.context) })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: agentJwk }).sign(agent.privateKey);
    return { authorization: `DPoP ${token}`, dpop: proof, body: JSON.stringify(body), method: endpoint.method, url: endpoint.url };
  }
  return { verifier, request };
}

test('real signatures and real persistent store verify a proof only once', async () => {
  const f = await flow('one-use');
  const request = await f.request();
  const result = await f.verifier.verifyProtectedRequest(request);
  assert.equal(result.proof_verified, true);
  assert.equal(result.authorization_effect, 'none');
  assert.equal(result.requires_admission, true);
  await assert.rejects(f.verifier.verifyProtectedRequest(request), { code: 'invalid_proof' });
});

test('body tampering fails before consuming the legitimate persistent nonce', async () => {
  const f = await flow('tamper');
  const request = await f.request();
  const bad = JSON.parse(request.body); bad.action_request.parameters.amount += 1;
  await assert.rejects(f.verifier.verifyProtectedRequest({ ...request, body: JSON.stringify(bad) }), { code: 'invalid_request' });
  assert.equal((await f.verifier.verifyProtectedRequest(request)).proof_verified, true);
});

test('eight concurrently signed checks of one request have exactly one success', async () => {
  const f = await flow('race');
  const request = await f.request();
  const results = await Promise.allSettled(Array.from({ length: 8 }, () => f.verifier.verifyProtectedRequest(request)));
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
  assert.equal(results.filter((r) => r.status === 'rejected' && r.reason.code === 'invalid_proof').length, 7);
});

test('closed database pool produces unavailable, never an authorization fallback', async () => {
  const separate = new pg.Pool(testConnection());
  const f = await flow('outage', separate);
  const request = await f.request();
  await separate.end();
  await assert.rejects(f.verifier.verifyProtectedRequest(request), { code: 'temporarily_unavailable' });
});
