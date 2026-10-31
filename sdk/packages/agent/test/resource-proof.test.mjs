import assert from 'node:assert/strict';
import { createHash, sign as nodeSign } from 'node:crypto';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from 'jose';

import { createNonceChallengeVerifier } from '@atum/verification/nonce-challenge';
import { actionHash, intentHash } from '@atum/verification/context';
import { createVerifier, VerificationError } from '@atum/verification';
import { AgentError, createAgentKey } from '../src/key.mjs';
import { createProtectedRequestSigner } from '../src/resource-proof.mjs';

const NOW = 1_800_000_000_000;
const endpoint = { method: 'POST', url: 'https://resource.example.test/v1/orders' };
const action_request = { action: 'order.preview', parameters: { resource: 'ENERGY', amount: 2, duration: 30, max_price_sun: 0 + 9 } };
const energy_action = { action: 'energy.purchase', parameters: {
  network: 'tron-mainnet', resource: 'ENERGY', amount: 65_000, duration_sec: 3_600,
  recipient: 'TA4Wt1DUCqz6YegbnsmqsWC5uUfbdBqPxm', execution_provider: 'powersun-merx',
  quote_id: '123e4567-e89b-42d3-a456-426614174000', quote_expires_at_ms: NOW + 300_000,
  resource_cost_sun: '1105000', platform_fee_sun: '0', activation_fee_cap_sun: '100000',
  network_fee_cap_sun: '0', max_total_debit_sun: '1205000',
} };
const contextBase = {
  protocol_version: '0.1.0-draft.2', resource_profile_version: 'v1-draft.1',
  resource_profile_hash: 'sha256:dc6f6409a47da2a97ea7b4ace313985d7fcd4c6b8459a59ea06b014de304a175',
  issuer: 'https://issuer.example.test', audience: 'atum-api', environment: 'sandbox',
  tenant_id: 'tenant', resource_id: 'resource', quota_scope_id: 'quota', operation_namespace: 'orders',
  scoped_subject: 'subject', operation_id: 'operation', grant_id: 'grant', grant_version: 1,
  consent_hash: `sha256:${'a'.repeat(64)}`, account_binding_id: 'account', account_binding_version: 1,
  action: action_request.action, action_hash: actionHash(action_request), policy_version: 'policy',
};
const registration = {
  issuer: contextBase.issuer, audience: contextBase.audience, environment: contextBase.environment,
  tenant_id: contextBase.tenant_id, resource_id: contextBase.resource_id, quota_scope_id: contextBase.quota_scope_id,
  operation_namespace: contextBase.operation_namespace, resource_profile_version: contextBase.resource_profile_version,
  resource_profile_hash: contextBase.resource_profile_hash, policy_version: contextBase.policy_version,
  account_required_actions: ['order.preview'],
};
const nonce = Buffer.alloc(32, 7).toString('base64url');

function decoded(compact) {
  const [protectedHeader, payload] = compact.split('.');
  return {
    header: JSON.parse(Buffer.from(protectedHeader, 'base64url')),
    claims: JSON.parse(Buffer.from(payload, 'base64url')),
  };
}

function agentCode(code) {
  return error => error instanceof AgentError && error.code === code && !Object.hasOwn(error, 'cause');
}

class ReplayStore {
  constructor() { this.nonces = new Set(); this.proofs = new Set(); }
  issue(input) { this.nonces.add(JSON.stringify(input)); }
  async consume(input) {
    const nonceKey = JSON.stringify({ issuer: input.issuer, audience: input.audience,
      agent_key_thumbprint: input.agent_key_thumbprint, endpoint_url: input.endpoint_url, nonce: input.nonce });
    const proofKey = `${input.agent_key_thumbprint}:${input.proof_jti}`;
    if (!this.nonces.delete(nonceKey) || this.proofs.has(proofKey)) return false;
    this.proofs.add(proofKey); return true;
  }
}

async function fixture(overrides = {}) {
  const issuer = await generateKeyPair('RS256', { modulusLength: 2048 });
  const agent = await generateKeyPair('ES256');
  const issuerJwk = { ...(await exportJWK(issuer.publicKey)), kid: 'issuer-resource', alg: 'RS256', use: 'sig' };
  const publicJwk = await exportJWK(agent.publicKey);
  const thumbprint = await calculateJwkThumbprint(publicJwk, 'sha256');
  const selectedAction = overrides.energy ? energy_action : action_request;
  const context = { ...contextBase, ...(overrides.energy ? {
    resource_profile_version: 'merx.energy-purchase.v1-draft.1',
      resource_profile_hash: 'sha256:e1c5106dc710ce0ba3d846f3cb376358eb858c35adfbac906f0ff58f3a6451fa',
    environment: 'production', operation_namespace: 'energy', action: selectedAction.action,
    action_hash: actionHash(selectedAction),
  } : {}), agent_key_thumbprint: thumbprint };
  const configuredRegistration = overrides.energy ? {
    ...registration, environment: context.environment, operation_namespace: context.operation_namespace,
    resource_profile_version: context.resource_profile_version, resource_profile_hash: context.resource_profile_hash,
    account_required_actions: ['energy.purchase'],
  } : registration;
  let signs = 0;
  const key = await createAgentKey({ publicJwk, timeoutMs: overrides.keyTimeoutMs ?? 5000, sign: async data => {
    signs += 1;
    if (overrides.sign) return overrides.sign(data, agent.privateKey);
    return nodeSign('sha256', data, { key: agent.privateKey, dsaEncoding: 'ieee-p1363' });
  } });
  const clock = overrides.clock ?? (() => ({ now_ms: NOW, uncertainty_ms: 0, healthy: true }));
  const signer = createProtectedRequestSigner({ key, registration: configuredRegistration, endpoint, clock, timeoutMs: overrides.timeoutMs ?? 5000 });
  const token = await new SignJWT({
    iss: context.issuer, aud: context.audience, sub: context.scoped_subject, client_id: 'client1', jti: 'token-jti',
    iat: NOW / 1000 - 1, exp: NOW / 1000 + 120, cnf: { jkt: thumbprint }, scope: 'atum:invoke',
    atum: Object.fromEntries(['environment', 'tenant_id', 'resource_id', 'quota_scope_id', 'operation_namespace',
      'resource_profile_version', 'resource_profile_hash', 'policy_version', 'grant_id', 'grant_version', 'consent_hash',
      'account_binding_id', 'account_binding_version'].map(field => [field, context[field]])
      .concat([['proof_profile', 'atum-dpop-v1-draft.1']])),
  }).setProtectedHeader({ typ: 'at+jwt', alg: 'RS256', kid: issuerJwk.kid }).sign(issuer.privateKey);
  const store = new ReplayStore();
  const verifierConfig = { registration: configuredRegistration, issuerKeys: [issuerJwk], endpoint, clock };
  return { signer, key, token, context, store, verifierConfig, action: selectedAction, signs: () => signs };
}

test('signs exact protected and nonce-challenge requests accepted by unchanged public verifiers', async () => {
  const f = await fixture();
  const challenge = await f.signer.signChallenge({ access_token: f.token, context: f.context, action_request });
  const challengeProof = decoded(challenge.dpop);
  assert.deepEqual(Object.keys(challengeProof.claims).sort(), ['ath', 'atum_intent_hash', 'htm', 'htu', 'iat', 'jti']);
  assert.equal(challengeProof.claims.ath, createHash('sha256').update(f.token, 'ascii').digest('base64url'));
  assert.equal(challengeProof.claims.atum_intent_hash, intentHash(f.context));
  assert.deepEqual(challengeProof.header, { alg: 'ES256', jwk: f.key.publicJwk, typ: 'dpop+jwt' });
  const challengeVerifier = await createNonceChallengeVerifier(f.verifierConfig);
  const issued = await challengeVerifier.verifyNonceChallengeRequest(challenge, { deadlineAt: performance.now() + 1000 });
  assert.equal(issued.nonce_issue_only, true);

  const request = await f.signer.sign({ access_token: f.token, context: f.context, action_request, nonce });
  const proof = decoded(request.dpop);
  assert.deepEqual(Object.keys(proof.claims).sort(), ['ath', 'atum_intent_hash', 'htm', 'htu', 'iat', 'jti', 'nonce']);
  assert.equal(proof.claims.nonce, nonce);
  assert.notEqual(proof.claims.jti, challengeProof.claims.jti);
  assert.deepEqual(Object.fromEntries(Object.entries(proof.claims).filter(([field]) => !['jti', 'nonce'].includes(field))),
    Object.fromEntries(Object.entries(challengeProof.claims).filter(([field]) => field !== 'jti')));
  assert.equal(request.body, challenge.body);
  assert.equal(request.authorization, challenge.authorization);
  assert.equal(request.body, `{"context":${JSON.stringify(Object.fromEntries(Object.entries(f.context).sort()))},"action_request":{"action":"order.preview","parameters":{"amount":2,"duration":30,"max_price_sun":9,"resource":"ENERGY"}}}`);
  assert.deepEqual({ authorization: request.authorization, method: request.method, url: request.url },
    { authorization: `DPoP ${f.token}`, method: endpoint.method, url: endpoint.url });
  assert.equal(Object.isFrozen(request), true);

  f.store.issue({ issuer: f.context.issuer, audience: f.context.audience, agent_key_thumbprint: f.context.agent_key_thumbprint,
    endpoint_url: endpoint.url, nonce });
  const verifier = await createVerifier({ ...f.verifierConfig, replayStore: f.store });
  const result = await verifier.verifyProtectedRequest(request);
  assert.equal(result.proof_verified, true);
  assert.equal(result.authorization_effect, 'none');
  assert.equal(result.requires_admission, true);
});

test('Agent signs and verifier accepts the exact production Energy intent', async () => {
  const f = await fixture({ energy: true });
  const request = await f.signer.sign({ access_token: f.token, context: f.context, action_request: f.action, nonce });
  assert.equal(JSON.parse(request.body).action_request.action, 'energy.purchase');
  assert.equal(decoded(request.dpop).claims.atum_intent_hash, intentHash(f.context));
  f.store.issue({ issuer: f.context.issuer, audience: f.context.audience,
    agent_key_thumbprint: f.context.agent_key_thumbprint, endpoint_url: endpoint.url, nonce });
  const verifier = await createVerifier({ ...f.verifierConfig, replayStore: f.store });
  const result = await verifier.verifyProtectedRequest(request);
  assert.equal(result.proof_verified, true);
  const invalid = structuredClone(f.action);
  invalid.parameters.recipient = `${invalid.parameters.recipient.slice(0, -1)}n`;
  await assert.rejects(f.signer.sign({ access_token: f.token, context: f.context, action_request: invalid, nonce }),
    agentCode('invalid_request'));
});

test('snapshots intent before await and emits a fresh JTI for the same stable operation', async () => {
  let release;
  const f = await fixture({ sign: async (data, privateKey) => new Promise(resolve => {
    release = () => resolve(nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' }));
  }) });
  const context = structuredClone(f.context); const action = structuredClone(action_request);
  const pending = f.signer.sign({ access_token: f.token, context, action_request: action, nonce });
  while (!release) await delay(1);
  context.operation_id = 'mutated'; action.parameters.amount = 99; release();
  const first = await pending;
  release = undefined;
  const secondPending = f.signer.sign({ access_token: f.token, context: f.context, action_request, nonce });
  while (!release) await delay(1);
  release();
  const second = await secondPending;
  assert.equal(JSON.parse(first.body).context.operation_id, 'operation');
  assert.equal(JSON.parse(first.body).action_request.parameters.amount, 2);
  assert.notEqual(decoded(first.dpop).claims.jti, decoded(second.dpop).claims.jti);
});

test('treats a bounded compact access token as opaque while hashing its exact ASCII bytes', async () => {
  const f = await fixture();
  const opaque = 'not-a-jwt.still-opaque.signature';
  const result = await f.signer.signChallenge({ access_token: opaque, context: f.context, action_request });
  assert.equal(result.authorization, `DPoP ${opaque}`);
  assert.equal(decoded(result.dpop).claims.ath, createHash('sha256').update(opaque, 'ascii').digest('base64url'));
});

test('rejects invalid binding, nonce, token and closed inputs before signing', async () => {
  const f = await fixture(); const before = f.signs();
  const wrongContext = { ...f.context, agent_key_thumbprint: Buffer.alloc(32, 1).toString('base64url') };
  const wrongAction = { ...action_request, parameters: { ...action_request.parameters, amount: 3 } };
  const cases = [
    { access_token: f.token, context: wrongContext, action_request, nonce },
    { access_token: f.token, context: f.context, action_request: wrongAction, nonce },
    { access_token: f.token, context: f.context, action_request, nonce: 'not-canonical' },
    { access_token: `a.${'x'.repeat(16384)}.b`, context: f.context, action_request, nonce },
    { access_token: 'a.b.é', context: f.context, action_request, nonce },
    { access_token: 'a.b.c\n', context: f.context, action_request, nonce },
    { access_token: f.token, context: f.context, action_request, nonce, extra: true },
  ];
  for (const input of cases) await assert.rejects(f.signer.sign(input), agentCode('invalid_request'));
  assert.equal(f.signs(), before);

  let getterCalls = 0;
  const accessor = { access_token: f.token, context: f.context, action_request, nonce };
  Object.defineProperty(accessor, 'nonce', { enumerable: true, get() { getterCalls += 1; return nonce; } });
  await assert.rejects(f.signer.sign(accessor), agentCode('invalid_request'));
  await assert.rejects(f.signer.signChallenge({ access_token: f.token, context: f.context,
    action_request, nonce }), agentCode('invalid_request'));
  await assert.rejects(f.signer.signChallenge({ access_token: f.token, context: f.context,
    action_request, nonce: 'malformed' }), agentCode('invalid_request'));
  await assert.rejects(f.signer.signChallenge({ access_token: f.token, context: f.context,
    action_request, extra: true }), agentCode('invalid_request'));
  assert.equal(getterCalls, 0);
});

test('snapshots closed trusted configuration and rejects invalid endpoints or registrations', async () => {
  const f = await fixture();
  const mutableRegistration = structuredClone(registration);
  const mutableEndpoint = { ...endpoint };
  const signer = createProtectedRequestSigner({ key: f.key, registration: mutableRegistration,
    endpoint: mutableEndpoint, clock: () => ({ now_ms: NOW, uncertainty_ms: 0, healthy: true }) });
  mutableRegistration.policy_version = 'changed'; mutableEndpoint.url = 'https://other.example/test';
  const result = await signer.signChallenge({ access_token: f.token, context: f.context, action_request });
  assert.equal(result.url, endpoint.url);

  const invalid = [
    { key: f.key, registration: { ...registration, extra: true }, endpoint, clock: () => ({ now_ms: NOW, uncertainty_ms: 0, healthy: true }) },
    { key: f.key, registration: { ...registration, environment: 'production' }, endpoint, clock: () => ({ now_ms: NOW, uncertainty_ms: 0, healthy: true }) },
    { key: f.key, registration: { ...registration, issuer: `${registration.issuer}\n` }, endpoint, clock: () => ({ now_ms: NOW, uncertainty_ms: 0, healthy: true }) },
    { key: f.key, registration: { ...registration, issuer: [registration.issuer] }, endpoint, clock: () => ({ now_ms: NOW, uncertainty_ms: 0, healthy: true }) },
    { key: f.key, registration: { ...registration, audience: [registration.audience] }, endpoint, clock: () => ({ now_ms: NOW, uncertainty_ms: 0, healthy: true }) },
    { key: f.key, registration: { ...registration, resource_profile_hash: [registration.resource_profile_hash] }, endpoint, clock: () => ({ now_ms: NOW, uncertainty_ms: 0, healthy: true }) },
    { key: f.key, registration, endpoint: { method: 'GET', url: endpoint.url }, clock: () => ({ now_ms: NOW, uncertainty_ms: 0, healthy: true }) },
    { key: f.key, registration, endpoint: { method: 'POST', url: `${endpoint.url}?target=other` }, clock: () => ({ now_ms: NOW, uncertainty_ms: 0, healthy: true }) },
    { key: f.key, registration, endpoint, clock: () => ({ now_ms: NOW, uncertainty_ms: 0, healthy: true }), timeoutMs: 5001 },
  ];
  for (const config of invalid) assert.throws(() => createProtectedRequestSigner(config), TypeError);
});

test('absolute deadline and measured clock fence a stalled or late key without returning a proof', async () => {
  const stalled = await fixture({ timeoutMs: 25, keyTimeoutMs: 100, sign: async () => new Promise(() => {}) });
  const started = performance.now();
  await assert.rejects(stalled.signer.sign({ access_token: stalled.token, context: stalled.context, action_request, nonce }),
    agentCode('temporarily_unavailable'));
  assert.ok(performance.now() - started < 250);

  let now = NOW;
  const late = await fixture({ clock: () => ({ now_ms: now, uncertainty_ms: 0, healthy: true }), sign: async (data, privateKey) => {
    now += 61_000;
    return nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  } });
  await assert.rejects(late.signer.sign({ access_token: late.token, context: late.context, action_request, nonce }),
    agentCode('temporarily_unavailable'));

  const unhealthy = await fixture({ clock: () => ({ now_ms: NOW, uncertainty_ms: 0, healthy: false }) });
  await assert.rejects(unhealthy.signer.sign({ access_token: unhealthy.token, context: unhealthy.context, action_request, nonce }),
    agentCode('temporarily_unavailable'));

  const times = [NOW, NOW - 1];
  const backwards = await fixture({ clock: () => ({ now_ms: times.shift(), uncertainty_ms: 0, healthy: true }) });
  await assert.rejects(backwards.signer.sign({ access_token: backwards.token, context: backwards.context, action_request, nonce }),
    agentCode('temporarily_unavailable'));
});

test('public verifier rejects nonce, endpoint, body and proof substitutions', async () => {
  const mutations = [
    request => ({ ...request, url: 'https://resource.example.test/v1/other' }),
    request => ({ ...request, body: request.body.replace('"amount":2', '"amount":3') }),
    request => ({ ...request, dpop: `${request.dpop.slice(0, -1)}${request.dpop.endsWith('A') ? 'B' : 'A'}` }),
  ];
  for (const mutate of mutations) {
    const f = await fixture();
    const request = await f.signer.sign({ access_token: f.token, context: f.context, action_request, nonce });
    f.store.issue({ issuer: f.context.issuer, audience: f.context.audience, agent_key_thumbprint: f.context.agent_key_thumbprint,
      endpoint_url: endpoint.url, nonce });
    const verifier = await createVerifier({ ...f.verifierConfig, replayStore: f.store });
    await assert.rejects(verifier.verifyProtectedRequest(mutate(request)),
      error => error instanceof VerificationError && ['invalid_request', 'invalid_proof'].includes(error.code));
  }

  const f = await fixture();
  const substituted = await f.signer.sign({ access_token: f.token, context: f.context, action_request,
    nonce: Buffer.alloc(32, 8).toString('base64url') });
  f.store.issue({ issuer: f.context.issuer, audience: f.context.audience,
    agent_key_thumbprint: f.context.agent_key_thumbprint, endpoint_url: endpoint.url, nonce });
  const verifier = await createVerifier({ ...f.verifierConfig, replayStore: f.store });
  await assert.rejects(verifier.verifyProtectedRequest(substituted),
    error => error instanceof VerificationError && error.code === 'invalid_proof');
});
