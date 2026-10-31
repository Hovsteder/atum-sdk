import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from 'jose';

import { actionHash, canonicalAction, intentHash, validateBoundIntent } from '../src/context.mjs';
import { createVerifier } from '../src/verifier.mjs';
import {
  GENERIC_SERVICE_PROFILE,
  MERX_SANDBOX_V1,
  canonicalServiceDescriptor,
  hashServiceDescriptor,
  normalizeProfileAction,
  normalizeProfileGrant,
  validateResourceRegistration,
} from '../src/resource-profiles.mjs';

const vectors = JSON.parse(readFileSync(new URL('../../../protocol/resource-profiles/atum.service-actions.v1-draft.1.vectors.json', import.meta.url)));
const descriptor = vectors.descriptor;
const registration = {
  issuer: 'https://issuer.example', audience: 'https://calendar.example', environment: 'sandbox',
  tenant_id: 'calendar', resource_id: 'calendar-api', quota_scope_id: 'owner', operation_namespace: 'calendar-operations',
  resource_profile_version: GENERIC_SERVICE_PROFILE, resource_profile_hash: vectors.descriptor_hash,
  policy_version: 'owner-passkey-v1', account_required_actions: ['storage.object.write'],
};

function contextFor(request, binding = null) {
  return {
    protocol_version: '0.1.0-draft.2', resource_profile_version: registration.resource_profile_version,
    resource_profile_hash: registration.resource_profile_hash, issuer: registration.issuer, audience: registration.audience,
    environment: registration.environment, tenant_id: registration.tenant_id, resource_id: registration.resource_id,
    quota_scope_id: registration.quota_scope_id, operation_namespace: registration.operation_namespace,
    scoped_subject: 'owner-1', operation_id: 'operation-1', grant_id: 'grant-1', grant_version: 1,
    policy_version: registration.policy_version, agent_key_thumbprint: Buffer.alloc(32).toString('base64url'),
    consent_hash: `sha256:${'0'.repeat(64)}`, action_hash: actionHash(request, descriptor),
    account_binding_id: binding, account_binding_version: binding === null ? null : 1, action: request.action,
  };
}

test('trusted generic descriptor and unrelated action names share canonical known answers', () => {
  assert.equal(canonicalServiceDescriptor(descriptor), vectors.canonical_descriptor);
  assert.equal(hashServiceDescriptor(descriptor), vectors.descriptor_hash);
  const selected = validateResourceRegistration(registration, descriptor);
  assert.equal(selected.profile.profile, GENERIC_SERVICE_PROFILE);
  for (const vector of vectors.actions) {
    assert.deepEqual(normalizeProfileAction(vector.request, selected.profile), vector.request);
    assert.equal(canonicalAction(vector.request, descriptor), vector.canonical);
    assert.equal(actionHash(vector.request, descriptor), vector.hash);
  }
});

test('generic registration binds the immutable descriptor and exact account-required subset', () => {
  for (const [changedRegistration, changedDescriptor] of [
    [{ ...registration, resource_profile_hash: `sha256:${'0'.repeat(64)}` }, descriptor],
    [registration, { ...descriptor, actions: [...descriptor.actions, 'mail.message.send'] }],
    [{ ...registration, account_required_actions: [] }, descriptor],
    [{ ...registration, resource_profile_version: 'unknown' }, descriptor],
  ]) assert.throws(() => validateResourceRegistration(changedRegistration, changedDescriptor), TypeError);
  assert.throws(() => validateResourceRegistration(registration), TypeError);
  const legacy = { ...registration, environment: 'sandbox', resource_profile_version: MERX_SANDBOX_V1.profile,
    resource_profile_hash: MERX_SANDBOX_V1.hash, account_required_actions: [] };
  const genericEnergy = { profile: GENERIC_SERVICE_PROFILE, actions: ['energy.purchase'], account_required_actions: [] };
  assert.throws(() => validateResourceRegistration(legacy, genericEnergy), TypeError);
});

test('generic action parameters are bounded canonical JSON and reject unknown permissions', () => {
  const selected = validateResourceRegistration(registration, descriptor).profile;
  assert.deepEqual(normalizeProfileGrant({ permissions: [{ action: 'calendar.event.read' }], grant_limit: 3,
    grant_expires_at_ms: 1_800_000_000_000 }, selected), {
    permissions: [{ action: 'calendar.event.read' }], grant_limit: 3, grant_expires_at_ms: 1_800_000_000_000,
  });
  for (const permission of [
    { action: 'calendar.event.read', restriction: null },
    { action: 'calendar.event.read', parameters: {} },
    { action: 'unknown.action' },
  ]) assert.throws(() => normalizeProfileGrant({ permissions: [permission], grant_limit: 1,
    grant_expires_at_ms: 1_800_000_000_000 }, selected), TypeError);
  for (const parameters of [
    { amount: 1.5 }, { amount: -0 }, { nested: { value: '\ud800' } },
    Object.fromEntries([['x', 'a'.repeat(16_384)]]),
  ]) assert.throws(() => normalizeProfileAction({ action: 'calendar.event.read', parameters }, selected), TypeError);
  const sparse = []; sparse.length = 1;
  const decorated = []; decorated.push('value'); decorated.extra = true;
  for (const parameters of [{ values: sparse }, { values: decorated }]) {
    assert.throws(() => normalizeProfileAction({ action: 'calendar.event.read', parameters }, selected), TypeError);
  }
  assert.throws(() => canonicalServiceDescriptor({ profile: GENERIC_SERVICE_PROFILE,
    actions: [`a.${'b'.repeat(127)}`], account_required_actions: [] }), TypeError);
});

test('generic bound intent checks descriptor membership, service registration and account policy', () => {
  const read = vectors.actions.find(item => item.request.action === 'calendar.event.read').request;
  const write = vectors.actions.find(item => item.request.action === 'storage.object.write').request;
  assert.doesNotThrow(() => validateBoundIntent(contextFor(read), read, registration, descriptor));
  assert.doesNotThrow(() => validateBoundIntent(contextFor(write, 'binding-1'), write, registration, descriptor));
  assert.throws(() => validateBoundIntent(contextFor(write), write, registration, descriptor), TypeError);
  assert.throws(() => validateBoundIntent(contextFor(read), read, { ...registration, audience: 'https://other.example' }, descriptor), TypeError);
  assert.throws(() => validateBoundIntent(contextFor(read), { action: 'unknown.action', parameters: {} }, registration, descriptor), TypeError);
  assert.throws(() => validateBoundIntent(contextFor(read), read, registration), TypeError);
});

test('actual signed token and DPoP proof require the trusted generic descriptor', async () => {
  const now = 1_800_000_000_000;
  const endpoint = { method: 'POST', url: 'https://calendar.example/v1/atum/operations' };
  const issuer = await generateKeyPair('RS256', { modulusLength: 2048 });
  const agent = await generateKeyPair('ES256');
  const issuerPublic = { ...(await exportJWK(issuer.publicKey)), kid: 'issuer-1', alg: 'RS256', use: 'sig' };
  const agentPublic = await exportJWK(agent.publicKey);
  const request = vectors.actions[0].request;
  const bound = contextFor(request);
  bound.agent_key_thumbprint = await calculateJwkThumbprint(agentPublic, 'sha256');
  const atum = Object.fromEntries(['environment', 'tenant_id', 'resource_id', 'quota_scope_id',
    'operation_namespace', 'resource_profile_version', 'resource_profile_hash', 'policy_version',
    'grant_id', 'grant_version', 'consent_hash', 'account_binding_id', 'account_binding_version']
    .map(key => [key, bound[key]]));
  atum.proof_profile = 'atum-dpop-v1-draft.1';
  const token = await new SignJWT({ iss: bound.issuer, aud: bound.audience, sub: bound.scoped_subject,
    client_id: 'calendar-agent', jti: 'token-1', iat: now / 1000 - 1, exp: now / 1000 + 120,
    cnf: { jkt: bound.agent_key_thumbprint }, scope: 'atum:invoke', atum })
    .setProtectedHeader({ typ: 'at+jwt', alg: 'RS256', kid: 'issuer-1' }).sign(issuer.privateKey);
  const nonce = randomBytes(32).toString('base64url');
  const proof = await new SignJWT({ jti: randomBytes(16).toString('base64url'), htm: endpoint.method,
    htu: endpoint.url, iat: now / 1000, ath: createHash('sha256').update(token, 'ascii').digest('base64url'),
    nonce, atum_intent_hash: intentHash(bound, descriptor) })
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: agentPublic }).sign(agent.privateKey);
  const verifier = await createVerifier({ registration, descriptor, issuerKeys: [issuerPublic], endpoint,
    clock: () => ({ now_ms: now, uncertainty_ms: 0, healthy: true }), replayStore: { consume: async () => true } });
  const result = await verifier.verifyProtectedRequest({ authorization: `DPoP ${token}`, dpop: proof,
    body: JSON.stringify({ context: bound, action_request: request }), method: endpoint.method, url: endpoint.url });
  assert.equal(result.proof_verified, true);
  assert.equal(result.authorization_effect, 'none');
  await assert.rejects(() => createVerifier({ registration, issuerKeys: [issuerPublic], endpoint,
    clock: () => ({ now_ms: now, uncertainty_ms: 0, healthy: true }), replayStore: { consume: async () => true } }), TypeError);
});
