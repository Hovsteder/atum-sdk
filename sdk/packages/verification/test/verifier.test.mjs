import assert from 'node:assert/strict';
import test from 'node:test';
import { generateKeyPair, exportJWK, SignJWT, calculateJwkThumbprint } from 'jose';

import { createVerifier, VerificationError } from '../src/verifier.mjs';
import { actionHash, intentHash } from '../src/context.mjs';

const endpoint = { method: 'POST', url: 'https://sandbox.example.test/v1/protected' };
const now = 1_800_000_000_000;
const context = {
  protocol_version: '0.1.0-draft.2', resource_profile_version: 'v1-draft.1',
  resource_profile_hash: 'sha256:dc6f6409a47da2a97ea7b4ace313985d7fcd4c6b8459a59ea06b014de304a175',
  issuer: 'https://issuer.example.test', audience: 'atum-api', environment: 'sandbox',
  tenant_id: 'tenant', resource_id: 'resource', quota_scope_id: 'quota', operation_namespace: 'orders',
  scoped_subject: 'subject', operation_id: 'operation', grant_id: 'grant', grant_version: 1,
  agent_key_thumbprint: '', consent_hash: `sha256:${'a'.repeat(64)}`,
  account_binding_id: 'account', account_binding_version: 1, action_hash: '', action: 'order.preview', policy_version: 'policy',
};
const action_request = { action: 'order.preview', parameters: { resource: 'ENERGY', amount: 1, duration: 30 } };
const registration = Object.fromEntries([
  'issuer', 'audience', 'environment', 'tenant_id', 'resource_id', 'quota_scope_id',
  'operation_namespace', 'resource_profile_version', 'resource_profile_hash', 'policy_version',
].map((key) => [key, context[key]]));
registration.account_required_actions = ['order.preview'];

function b64(bytes) { return Buffer.from(bytes).toString('base64url'); }
function clone(value) { return structuredClone(value); }

class AtomicReplayStore {
  constructor() { this.used = new Set(); this.nonces = new Set(); }
  issue({ issuer, audience, agent_key_thumbprint, endpoint_url, nonce }) {
    this.nonces.add(JSON.stringify({ issuer, audience, agent_key_thumbprint, endpoint_url, nonce }));
  }
  async consume(input) {
    const nonceKey = JSON.stringify({ issuer: input.issuer, audience: input.audience, agent_key_thumbprint: input.agent_key_thumbprint, endpoint_url: input.endpoint_url, nonce: input.nonce });
    const proofKey = JSON.stringify([input.issuer, input.audience, input.agent_key_thumbprint, input.proof_jti]);
    if (!this.nonces.has(nonceKey) || this.used.has(proofKey)) return false;
    this.nonces.delete(nonceKey); this.used.add(proofKey); return true;
  }
}

async function fixture() {
  const issuer = await generateKeyPair('RS256', { modulusLength: 2048 });
  const agent = await generateKeyPair('ES256');
  const issuerPublic = await exportJWK(issuer.publicKey); issuerPublic.kid = 'issuer-1'; issuerPublic.alg = 'RS256'; issuerPublic.use = 'sig';
  const agentPublic = await exportJWK(agent.publicKey);
  const thumbprint = await calculateJwkThumbprint(agentPublic, 'sha256');
  const fullContext = clone(context); fullContext.agent_key_thumbprint = thumbprint;
  fullContext.action_hash = actionHash(action_request);
  const store = new AtomicReplayStore();
  const verifier = await createVerifier({ registration, issuerKeys: [issuerPublic], endpoint, clock: () => ({ now_ms: now, uncertainty_ms: 0, healthy: true }), replayStore: store });
  return { issuer, agent, agentPublic, fullContext, store, verifier };
}

async function signedRequest(f, changes = {}) {
  const bodyContext = changes.context ?? f.fullContext;
  const ctx = changes.token_context ?? bodyContext;
  const body = JSON.stringify({ context: bodyContext, action_request: changes.action_request ?? action_request });
  const token = await new SignJWT({
    iss: ctx.issuer, aud: ctx.audience, sub: ctx.scoped_subject, client_id: 'client1', jti: 'tokenjti',
    iat: now / 1000 - 1, exp: now / 1000 + 120, cnf: { jkt: ctx.agent_key_thumbprint }, scope: 'atum:invoke',
    atum: Object.fromEntries(['environment', 'tenant_id', 'resource_id', 'quota_scope_id', 'operation_namespace', 'resource_profile_version', 'resource_profile_hash', 'policy_version', 'grant_id', 'grant_version', 'consent_hash', 'account_binding_id', 'account_binding_version'].map((key) => [key, ctx[key]]).concat([['proof_profile', 'atum-dpop-v1-draft.1']])),
  }).setProtectedHeader({ typ: 'at+jwt', alg: 'RS256', kid: 'issuer-1' }).sign(f.issuer.privateKey);
  const nonce = changes.nonce ?? b64(crypto.getRandomValues(new Uint8Array(32)));
  if (!changes.noIssue) f.store.issue({ issuer: bodyContext.issuer, audience: bodyContext.audience, agent_key_thumbprint: bodyContext.agent_key_thumbprint, endpoint_url: endpoint.url, nonce });
  const proof = await new SignJWT({ jti: changes.proof_jti ?? b64(crypto.getRandomValues(new Uint8Array(16))), htm: changes.htm ?? endpoint.method, htu: changes.htu ?? endpoint.url, iat: changes.proof_iat ?? now / 1000, ath: changes.ath ?? b64((await import('node:crypto')).createHash('sha256').update(token, 'ascii').digest()), nonce, atum_intent_hash: changes.intent ?? intentHash(bodyContext) })
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: f.agentPublic }).sign(f.agent.privateKey);
  return { authorization: `DPoP ${token}`, dpop: proof, body, method: endpoint.method, url: endpoint.url };
}

async function rejects(fn, code = 'invalid_proof') {
  await assert.rejects(fn, (error) => error instanceof VerificationError && error.code === code && !Object.hasOwn(error, 'cause'));
}

test('verifies a fully bound synthetic RS256 token and ES256 proof without authorizing execution', async () => {
  const f = await fixture(); const result = await f.verifier.verifyProtectedRequest(await signedRequest(f));
  assert.deepEqual(Object.keys(result).sort(), ['authorization_effect', 'client_id', 'context', 'intent_hash', 'proof_jti', 'proof_verified', 'requires_admission', 'token_expires_at_ms']);
  assert.equal(result.proof_verified, true); assert.equal(result.authorization_effect, 'none'); assert.equal(result.requires_admission, true);
  assert.equal(Object.isFrozen(result), true); assert.equal(Object.isFrozen(result.context), true);
});

test('rejects validly signed tokens whose grant, account, environment, or intent differs from the body', async () => {
  for (const mutate of [
    (c) => { c.grant_id = 'other'; }, (c) => { c.account_binding_id = 'other'; },
    (c) => { c.environment = 'other'; }, (c) => { c.consent_hash = `sha256:${'b'.repeat(64)}`; },
    (c) => { c.issuer = 'https://other.example.test'; }, (c) => { c.audience = 'other-audience'; },
  ]) {
    const f = await fixture(); const tokenContext = clone(f.fullContext); mutate(tokenContext);
    const input = await signedRequest(f, { context: f.fullContext, token_context: tokenContext });
    await rejects(() => f.verifier.verifyProtectedRequest(input));
  }
});

test('rejects signed proof substitutions for ath, nonce, endpoint and stale proof time', async () => {
  for (const changes of [{ ath: b64(new Uint8Array(32)) }, { nonce: b64(new Uint8Array(32)), noIssue: true }, { htu: 'https://sandbox.example.test/elsewhere' }, { proof_iat: now / 1000 - 61 }]) {
    const f = await fixture(); const input = await signedRequest(f, changes);
    await rejects(() => f.verifier.verifyProtectedRequest(input));
  }
});

test('calls an atomic replay adapter after cryptographic checks, allowing at most one concurrent proof', async () => {
  const f = await fixture(); const input = await signedRequest(f);
  const outcomes = await Promise.allSettled([f.verifier.verifyProtectedRequest(input), f.verifier.verifyProtectedRequest(input)]);
  assert.equal(outcomes.filter((outcome) => outcome.status === 'fulfilled').length, 1);
  assert.equal(outcomes.filter((outcome) => outcome.status === 'rejected' && outcome.reason.code === 'invalid_proof').length, 1);
});

test('fails closed when the replay backend is unavailable and does not consume malformed requests', async () => {
  const f = await fixture(); const input = await signedRequest(f);
  f.verifier = await createVerifier({ registration, issuerKeys: [{ ...(await exportJWK(f.issuer.publicKey)), kid: 'issuer-1', alg: 'RS256', use: 'sig' }], endpoint, clock: () => ({ now_ms: now, uncertainty_ms: 0, healthy: true }), replayStore: { consume: async () => { throw new Error('outage'); } } });
  await rejects(() => f.verifier.verifyProtectedRequest(input), 'temporarily_unavailable');
});

test('classifies malformed request data separately and never calls replay for it', async () => {
  const f = await fixture(); const input = await signedRequest(f); let calls = 0;
  f.store.consume = async () => { calls += 1; return true; };
  // Install the spy before construction, since the factory intentionally binds consume.
  f.verifier = await createVerifier({ registration, endpoint,
    issuerKeys: [{ ...(await exportJWK(f.issuer.publicKey)), kid: 'issuer-1', alg: 'RS256', use: 'sig' }],
    clock: () => ({ now_ms: now, uncertainty_ms: 0, healthy: true }), replayStore: f.store });
  for (const malformed of [
    { ...input, body: '{"context":1,"context":2}' },
    { ...input, authorization: `DPoP ${'a'.repeat(16_412)}` },
    { ...input, body: 'x'.repeat(32_769) },
    { ...input, body: new Uint8Array(32_769) },
  ]) await rejects(() => f.verifier.verifyProtectedRequest(malformed), 'invalid_request');
  assert.equal(calls, 0);
});

test('snapshots adapters at factory creation and rechecks time immediately before replay', async () => {
  const f = await fixture(); const keys = [{ ...(await exportJWK(f.issuer.publicKey)), kid: 'issuer-1', alg: 'RS256', use: 'sig' }];
  let calls = 0; const config = { registration, issuerKeys: keys, endpoint, clock: () => ({ now_ms: now, uncertainty_ms: 0, healthy: true }), replayStore: { consume: async () => { calls += 1; return true; } } };
  const verifier = await createVerifier(config);
  config.clock = () => ({ now_ms: 0, uncertainty_ms: 0, healthy: false });
  config.replayStore.consume = async () => false;
  await verifier.verifyProtectedRequest(await signedRequest(f));
  assert.equal(calls, 1);
  let tick = 0;
  const expiring = await createVerifier({ registration, issuerKeys: keys, endpoint, clock: () => ({ now_ms: tick++ === 0 ? now : now + 121_000, uncertainty_ms: 0, healthy: true }), replayStore: f.store });
  const input = await signedRequest(f);
  await rejects(() => expiring.verifyProtectedRequest(input));
});

test('fails closed for unsafe clocks, backward clock movement, and altered JOSE types', async () => {
  const f = await fixture(); const keys = [{ ...(await exportJWK(f.issuer.publicKey)), kid: 'issuer-1', alg: 'RS256', use: 'sig' }];
  for (const clock of [
    () => ({ now_ms: now, uncertainty_ms: 0, healthy: false }),
    () => ({ now_ms: 8_640_000_000_000_001, uncertainty_ms: 0, healthy: true }),
  ]) {
    const verifier = await createVerifier({ registration, issuerKeys: keys, endpoint, clock, replayStore: f.store });
    const input = await signedRequest(f);
    await rejects(() => verifier.verifyProtectedRequest(input), 'temporarily_unavailable');
  }
  let tick = 0;
  const backward = await createVerifier({ registration, issuerKeys: keys, endpoint, clock: () => ({ now_ms: tick++ === 0 ? now : now - 1, uncertainty_ms: 0, healthy: true }), replayStore: f.store });
  const backwardInput = await signedRequest(f);
  await rejects(() => backward.verifyProtectedRequest(backwardInput), 'temporarily_unavailable');
  const input = await signedRequest(f); const [header, payload, signature] = input.dpop.split('.');
  const changedHeader = b64(Buffer.from(JSON.stringify({ typ: 'wrong', alg: 'ES256', jwk: f.agentPublic })));
  input.dpop = `${changedHeader}.${payload}.${signature}`;
  await rejects(() => f.verifier.verifyProtectedRequest(input));
});
