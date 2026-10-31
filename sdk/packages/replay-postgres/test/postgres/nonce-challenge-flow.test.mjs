import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test, { after, before } from 'node:test';
import pg from 'pg';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createVerifier } from '@atum/verification';
import { createNonceChallengeVerifier, VerificationError } from '@atum/verification/nonce-challenge';
import { intentHash } from '@atum/verification/context';
import { createPostgresNonceChallengeStore } from '../../src/nonce-challenge.mjs';
import { createPostgresReplayStore } from '../../src/store.mjs';
import { testConnection } from '../../tools/test-connection.mjs';

const base = JSON.parse(await readFile(new URL('../../../verification/test/fixtures/proof-vectors.json', import.meta.url)));
const now = base.clock.now_ms;
const endpoint = base.endpoint;
let pool;
before(() => { pool = new pg.Pool(testConnection()); });
after(async () => { await pool?.end(); });

const deadline = () => ({ deadlineAt: performance.now() + 1000 });
const error = code => value => value instanceof VerificationError && value.code === code;

async function flow(name, grantId = 'grant-001') {
  const issuer = await generateKeyPair('RS256', { modulusLength: 2048 });
  const agent = await generateKeyPair('ES256');
  const issuerJwk = { ...(await exportJWK(issuer.publicKey)), kid: `nonce-flow-${name}`, alg: 'RS256', use: 'sig' };
  const agentJwk = await exportJWK(agent.publicKey);
  const thumbprint = await calculateJwkThumbprint(agentJwk, 'sha256');
  const body = JSON.parse(base.cases[0].input.body);
  body.context.issuer = `https://nonce-flow.atum.invalid/${process.pid}/${name}`;
  body.context.agent_key_thumbprint = thumbprint;
  body.context.grant_id = grantId;
  const registration = { ...base.registration, issuer: body.context.issuer,
    account_required_actions: ['prices.read', 'order.preview', 'sandbox.execute'] };
  const binding = { issuer: registration.issuer, audience: registration.audience, endpoint_url: endpoint.url };
  const clock = () => ({ now_ms: now, uncertainty_ms: 0, healthy: true });
  const nonceVerifier = await createNonceChallengeVerifier({ registration, issuerKeys: [issuerJwk], endpoint, clock });
  const replay = createPostgresReplayStore({ pool, binding, clock });
  const fullVerifier = await createVerifier({ registration, issuerKeys: [issuerJwk], endpoint, clock, replayStore: replay });
  const nonceStore = createPostgresNonceChallengeStore({ pool, binding, clock, maxActiveNoncesPerKey: 4 });
  const oldToken = JSON.parse(Buffer.from(base.cases[0].input.authorization.split(' ')[1].split('.')[1], 'base64url'));
  const token = await new SignJWT({ ...oldToken, iss: registration.issuer, cnf: { jkt: thumbprint },
    atum: { ...oldToken.atum, grant_id: grantId } })
    .setProtectedHeader({ typ: 'at+jwt', alg: 'RS256', kid: issuerJwk.kid }).sign(issuer.privateKey);

  async function request({ jti = randomBytes(16).toString('base64url'), nonce, proofKey = agent.privateKey, bodyOverride = body } = {}) {
    const claims = { jti, htm: endpoint.method, htu: endpoint.url, iat: now / 1000,
      ath: createHash('sha256').update(token, 'ascii').digest('base64url'), atum_intent_hash: intentHash(bodyOverride.context) };
    if (nonce !== undefined) claims.nonce = nonce;
    const dpop = await new SignJWT(claims)
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: agentJwk }).sign(proofKey);
    return { authorization: `DPoP ${token}`, dpop, body: JSON.stringify(bodyOverride), method: endpoint.method, url: endpoint.url };
  }

  return { body, binding, fullVerifier, nonceStore, nonceVerifier, request, thumbprint };
}

test('real signed omitted proof issues a durable nonce and a fresh full proof consumes it once', async () => {
  const f = await flow('happy');
  const initialJti = randomBytes(16).toString('base64url');
  const budget = deadline();
  const fact = await f.nonceVerifier.verifyNonceChallengeRequest(await f.request({ jti: initialJti }), budget);

  assert.deepEqual(fact, {
    nonce_issue_only: true, issuer: f.binding.issuer, audience: f.binding.audience, endpoint_url: f.binding.endpoint_url,
    agent_key_thumbprint: f.thumbprint, proof_jti: initialJti, intent_hash: intentHash(f.body.context),
    token_expires_at_ms: now + 120_000, proof_iat_ms: now, replay_expires_at_ms: now + 61_000,
    verified_now_ms: now, verified_upper_bound_ms: now,
  });

  const issued = await f.nonceStore.issueVerifiedNonce(fact, budget);
  assert.equal(issued.status, 'issued');
  assert.match(issued.nonce, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(issued.expires_at_ms, now + 30_000);

  await assert.rejects(f.fullVerifier.verifyProtectedRequest(await f.request({ jti: initialJti, nonce: issued.nonce })), error('invalid_proof'));

  const continuationJti = randomBytes(16).toString('base64url');
  assert.deepEqual(await f.fullVerifier.verifyProtectedRequest(await f.request({ jti: continuationJti, nonce: issued.nonce })), {
    proof_verified: true, authorization_effect: 'none', requires_admission: true,
    context: f.body.context, intent_hash: intentHash(f.body.context), client_id: 'synthetic-client',
    token_expires_at_ms: now + 120_000, proof_jti: continuationJti,
  });
  await assert.rejects(f.fullVerifier.verifyProtectedRequest(await f.request({ jti: randomBytes(16).toString('base64url'), nonce: issued.nonce })), error('invalid_proof'));
});

test('wrong signature, changed context, and present nonce cannot produce an issue fact or durable nonce', async () => {
  const f = await flow('negative');
  const impostor = await generateKeyPair('ES256');
  const changed = structuredClone(f.body);
  changed.context.tenant_id = 'different-tenant';
  const candidates = [
    [await f.request({ proofKey: impostor.privateKey }), 'invalid_proof'],
    [await f.request({ bodyOverride: changed }), 'invalid_request'],
    [await f.request({ nonce: 'not-a-valid-32-byte-nonce' }), 'invalid_proof'],
  ];
  for (const [input, code] of candidates) {
    await assert.rejects(f.nonceVerifier.verifyNonceChallengeRequest(input, deadline()), error(code));
  }
  const persisted = await pool.query('SELECT count(*)::int AS count FROM atum_request_proofs.proofs WHERE issuer = $1 AND audience = $2', [f.binding.issuer, f.binding.audience]);
  const nonces = await pool.query('SELECT count(*)::int AS count FROM atum_request_proofs.nonces WHERE issuer = $1 AND audience = $2', [f.binding.issuer, f.binding.audience]);
  assert.equal(persisted.rows[0].count, 0);
  assert.equal(nonces.rows[0].count, 0);
});

test('a revoked-grant label remains outside cryptographic nonce facts and authority decisions', async () => {
  const f = await flow('revoked', 'grant-revoked-outside-crypto');
  const fact = await f.nonceVerifier.verifyNonceChallengeRequest(await f.request(), deadline());
  assert.deepEqual(Object.keys(fact).sort(), ['agent_key_thumbprint', 'audience', 'endpoint_url', 'intent_hash', 'issuer',
    'nonce_issue_only', 'proof_iat_ms', 'proof_jti', 'replay_expires_at_ms', 'token_expires_at_ms',
    'verified_now_ms', 'verified_upper_bound_ms']);
  for (const field of ['grant_id', 'grant_version', 'consent_hash', 'context', 'proof_verified', 'authorization_effect', 'requires_admission']) {
    assert.equal(field in fact, false);
  }
  assert.equal(fact.nonce_issue_only, true);
});
