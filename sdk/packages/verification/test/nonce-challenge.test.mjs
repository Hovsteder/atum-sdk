import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import test from 'node:test';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from 'jose';

import { VerificationError } from '../src/verifier.mjs';
import { createNonceChallengeVerifier } from '../src/nonce-challenge.mjs';
import { actionHash, intentHash } from '../src/context.mjs';

const NOW = 1_800_000_000_000;
const endpoint = { method: 'POST', url: 'https://sandbox.example.test/v1/protected' };
const action = { action: 'order.preview', parameters: { resource: 'ENERGY', amount: 1, duration: 30 } };
const baseContext = {
  protocol_version: '0.1.0-draft.2', resource_profile_version: 'v1-draft.1',
  resource_profile_hash: 'sha256:dc6f6409a47da2a97ea7b4ace313985d7fcd4c6b8459a59ea06b014de304a175',
  issuer: 'https://issuer.example.test', audience: 'atum-api', environment: 'sandbox',
  tenant_id: 'tenant', resource_id: 'resource', quota_scope_id: 'quota', operation_namespace: 'orders',
  scoped_subject: 'subject', operation_id: 'operation', grant_id: 'grant', grant_version: 1,
  consent_hash: 'sha256:' + 'a'.repeat(64), account_binding_id: 'account', account_binding_version: 1,
  action: action.action, action_hash: actionHash(action), policy_version: 'policy',
};
const registration = {
  issuer: baseContext.issuer, audience: baseContext.audience, environment: baseContext.environment,
  tenant_id: baseContext.tenant_id, resource_id: baseContext.resource_id, quota_scope_id: baseContext.quota_scope_id,
  operation_namespace: baseContext.operation_namespace, resource_profile_version: baseContext.resource_profile_version,
  resource_profile_hash: baseContext.resource_profile_hash, policy_version: baseContext.policy_version,
  account_required_actions: ['order.preview'],
};

function code(value = 'invalid_proof') {
  return error => error instanceof VerificationError && error.code === value && !Object.hasOwn(error, 'cause');
}
function rejected(error) {
  return error instanceof VerificationError && ['invalid_proof', 'invalid_request'].includes(error.code);
}

async function fixture(clock = () => ({ now_ms: NOW, uncertainty_ms: 0, healthy: true })) {
  const issuer = await generateKeyPair('RS256', { modulusLength: 2048 });
  const agent = await generateKeyPair('ES256');
  const issuerJwk = { ...(await exportJWK(issuer.publicKey)), kid: 'nonce-test', alg: 'RS256', use: 'sig' };
  const agentJwk = await exportJWK(agent.publicKey);
  const thumbprint = await calculateJwkThumbprint(agentJwk, 'sha256');
  const context = { ...baseContext, agent_key_thumbprint: thumbprint };
  const config = { registration: structuredClone(registration), issuerKeys: [issuerJwk], endpoint: structuredClone(endpoint), clock };
  const verifier = await createNonceChallengeVerifier(config);
  return { issuer, agent, issuerJwk, agentJwk, thumbprint, context, verifier, config };
}

async function request(f, changes = {}) {
  const bodyContext = changes.context ?? f.context;
  const tokenContext = changes.tokenContext ?? bodyContext;
  const token = await new SignJWT({
    iss: tokenContext.issuer, aud: tokenContext.audience, sub: tokenContext.scoped_subject, client_id: 'client1',
    jti: 'token-jti', iat: NOW / 1000 - 1, exp: NOW / 1000 + 120, cnf: { jkt: tokenContext.agent_key_thumbprint },
    scope: changes.scope ?? 'atum:invoke',
    atum: Object.fromEntries(['environment', 'tenant_id', 'resource_id', 'quota_scope_id', 'operation_namespace',
      'resource_profile_version', 'resource_profile_hash', 'policy_version', 'grant_id', 'grant_version',
      'consent_hash', 'account_binding_id', 'account_binding_version'].map(key => [key, tokenContext[key]]).concat([['proof_profile', 'atum-dpop-v1-draft.1']])),
  }).setProtectedHeader({ typ: 'at+jwt', alg: 'RS256', kid: f.issuerJwk.kid }).sign(f.issuer.privateKey);
  const proofClaims = {
    jti: changes.proofJti ?? Buffer.alloc(16, 7).toString('base64url'), htm: changes.htm ?? endpoint.method,
    htu: changes.htu ?? endpoint.url, iat: changes.iat ?? NOW / 1000,
    ath: createHash('sha256').update(token, 'ascii').digest('base64url'),
    atum_intent_hash: changes.intentHash ?? intentHash(bodyContext),
    ...changes.proofExtra,
  };
  const proof = await new SignJWT(proofClaims).setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: f.agentJwk }).sign(f.agent.privateKey);
  return { authorization: 'DPoP ' + token, dpop: proof,
    body: JSON.stringify({ context: bodyContext, action_request: changes.action ?? action }), method: endpoint.method, url: endpoint.url };
}

test('real signed nonce-omitted proof returns only the frozen issue fact', async () => {
  const f = await fixture();
  const result = await f.verifier.verifyNonceChallengeRequest(await request(f), { deadlineAt: performance.now() + 1000 });
  assert.deepEqual(Object.keys(result).sort(), ['agent_key_thumbprint', 'audience', 'endpoint_url', 'intent_hash', 'issuer',
    'nonce_issue_only', 'proof_iat_ms', 'proof_jti', 'replay_expires_at_ms', 'token_expires_at_ms', 'verified_now_ms', 'verified_upper_bound_ms']);
  assert.equal(result.nonce_issue_only, true); assert.equal(result.agent_key_thumbprint, f.thumbprint);
  assert.equal(result.intent_hash, intentHash(f.context)); assert.equal(result.proof_iat_ms, NOW);
  assert.equal(result.replay_expires_at_ms, NOW + 61_000); assert.equal(result.token_expires_at_ms, NOW + 120_000);
  assert.equal(Object.isFrozen(result), true);
  assert.equal('proof_verified' in result, false); assert.equal('authorization_effect' in result, false);
  assert.equal('requires_admission' in result, false); assert.equal('context' in result, false);
  assert.throws(() => { result.proof_jti = 'changed'; }, TypeError);
});

test('present nonce, malformed proof fields, substitutions and invalid request body cannot issue', async () => {
  const f = await fixture();
  const alteredContext = { ...f.context, action_hash: 'sha256:' + 'b'.repeat(64) };
  const cases = [
    request(f, { proofExtra: { nonce: Buffer.alloc(32, 3).toString('base64url') } }),
    request(f, { proofExtra: { extra: true } }),
    request(f, { intentHash: 'sha256:' + '0'.repeat(64) }),
    request(f, { htu: 'https://sandbox.example.test/other' }),
    request(f, { iat: NOW / 1000 - 61 }),
    request(f, { scope: 'other' }),
    request(f, { context: alteredContext }),
    request(f, { action: { ...action, parameters: { ...action.parameters, amount: 2 } } }),
  ];
  for (const candidate of await Promise.all(cases)) {
    await assert.rejects(f.verifier.verifyNonceChallengeRequest(candidate, { deadlineAt: performance.now() + 1000 }), rejected);
  }
});

test('deadline and measured-clock movement fail closed after cryptographic work', async () => {
  const f = await fixture();
  const input = await request(f);
  await assert.rejects(f.verifier.verifyNonceChallengeRequest(input, { deadlineAt: performance.now() - 1 }), TypeError);
  await assert.rejects(f.verifier.verifyNonceChallengeRequest(input, { deadlineAt: performance.now() + 5001 }), TypeError);
  let tick = 0;
  const backwards = await fixture(() => ({ now_ms: tick++ === 0 ? NOW : NOW - 1, uncertainty_ms: 0, healthy: true }));
  await assert.rejects(backwards.verifier.verifyNonceChallengeRequest(await request(backwards), { deadlineAt: performance.now() + 1000 }), code('temporarily_unavailable'));
  tick = 0;
  const stale = await fixture(() => ({ now_ms: tick++ === 0 ? NOW : NOW + 61_000, uncertainty_ms: 0, healthy: true }));
  await assert.rejects(stale.verifier.verifyNonceChallengeRequest(await request(stale), { deadlineAt: performance.now() + 1000 }), code());
});

test('challenge sampling observes every awaited cryptographic step and retains the greatest upper bound', async () => {
  const samples = [
    { now_ms: NOW, uncertainty_ms: 0, healthy: true },
    { now_ms: NOW + 1, uncertainty_ms: 500, healthy: true },
    { now_ms: NOW + 2, uncertainty_ms: 0, healthy: true },
    { now_ms: NOW + 3, uncertainty_ms: 0, healthy: true },
    { now_ms: NOW + 4, uncertainty_ms: 0, healthy: true },
    { now_ms: NOW + 5, uncertainty_ms: 0, healthy: true },
  ];
  const f = await fixture(() => samples.shift());
  const result = await f.verifier.verifyNonceChallengeRequest(await request(f), { deadlineAt: performance.now() + 1000 });
  assert.equal(samples.length, 0);
  assert.equal(result.verified_now_ms, NOW + 5);
  assert.equal(result.verified_upper_bound_ms, NOW + 501);

  const backwards = [
    { now_ms: NOW, uncertainty_ms: 0, healthy: true },
    { now_ms: NOW + 1, uncertainty_ms: 0, healthy: true },
    { now_ms: NOW, uncertainty_ms: 0, healthy: true },
  ];
  const bad = await fixture(() => backwards.shift());
  await assert.rejects(bad.verifier.verifyNonceChallengeRequest(await request(bad), { deadlineAt: performance.now() + 1000 }), code('temporarily_unavailable'));
});

test('deadline options are captured from a single data descriptor without invoking accessors', async () => {
  const f = await fixture();
  let reads = 0;
  const options = {};
  Object.defineProperty(options, 'deadlineAt', { enumerable: true, get() { reads += 1; return performance.now() + 1000; } });
  await assert.rejects(f.verifier.verifyNonceChallengeRequest(await request(f), options), TypeError);
  assert.equal(reads, 0);
});

test('challenge snapshots normalized request input before returning its pending promise', async () => {
  const f = await fixture();
  const input = await request(f);
  const pending = f.verifier.verifyNonceChallengeRequest(input, { deadlineAt: performance.now() + 1000 });
  input.body = '{}';
  input.authorization = 'DPoP replaced';
  const result = await pending;
  assert.equal(result.nonce_issue_only, true);
  assert.equal(result.intent_hash, intentHash(f.context));
});

test('challenge deadline settles while WebCrypto verification is stalled', async () => {
  const f = await fixture();
  const prototype = Object.getPrototypeOf(globalThis.crypto.subtle);
  const original = prototype.verify;
  Object.defineProperty(prototype, 'verify', { value: () => new Promise(() => {}), writable: true, configurable: true, enumerable: true });
  try {
    const started = performance.now();
    await assert.rejects(f.verifier.verifyNonceChallengeRequest(await request(f), { deadlineAt: performance.now() + 25 }), code('temporarily_unavailable'));
    assert.ok(performance.now() - started < 250);
  } finally {
    Object.defineProperty(prototype, 'verify', { value: original, writable: true, configurable: true, enumerable: true });
  }
});

test('factory snapshots trusted dependencies and the package subpath preserves VerificationError identity', async () => {
  const f = await fixture();
  const config = f.config;
  const original = await request(f);
  const building = createNonceChallengeVerifier(config);
  config.clock = () => ({ now_ms: 0, uncertainty_ms: 0, healthy: false });
  config.endpoint.url = 'https://changed.example/test';
  config.issuerKeys[0].kid = 'changed';
  config.registration.policy_version = 'changed';
  const verifier = await building;
  const result = await verifier.verifyNonceChallengeRequest(original, { deadlineAt: performance.now() + 1000 });
  assert.equal(result.nonce_issue_only, true);
  const require = createRequire(import.meta.url);
  const loaded = require('@atum/verification/nonce-challenge');
  assert.equal(loaded.VerificationError, VerificationError);
  assert.equal(typeof loaded.createNonceChallengeVerifier, 'function');
});
