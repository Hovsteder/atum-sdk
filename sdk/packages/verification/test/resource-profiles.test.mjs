import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

import { actionHash, canonicalAction, validateBoundIntent } from '../src/context.mjs';

import {
  MERX_ENERGY_DESCRIPTOR_JSON,
  MERX_ENERGY_V1,
  MERX_SANDBOX_V1,
  normalizeProfileAction,
  normalizeProfileGrant,
  validateResourceRegistration,
} from '../src/resource-profiles.mjs';

const descriptorPath = new URL('../../../protocol/resource-profiles/merx.energy-purchase.v1-draft.1.json', import.meta.url);
const vectorsPath = new URL('../../../protocol/resource-profiles/merx.energy-purchase.v1-draft.1.vectors.json', import.meta.url);
const vectors = existsSync(vectorsPath) ? JSON.parse(readFileSync(vectorsPath)) : null;
const recipient = 'TA4Wt1DUCqz6YegbnsmqsWC5uUfbdBqPxm';
const parameters = Object.freeze({
  network: 'tron-mainnet',
  resource: 'ENERGY',
  amount: 65_000,
  duration_sec: 3_600,
  recipient,
  execution_provider: 'powersun-merx',
  quote_id: '123e4567-e89b-42d3-a456-426614174000',
  quote_expires_at_ms: 1_800_000_000_000,
  resource_cost_sun: '1105000',
  platform_fee_sun: '0',
  activation_fee_cap_sun: '100000',
  network_fee_cap_sun: '0',
  max_total_debit_sun: '1205000',
});
const permission = Object.freeze({ action: 'energy.purchase', parameters });
const registration = Object.freeze({
  issuer: 'https://issuer.example', audience: 'https://merx.example', environment: 'production',
  tenant_id: 'merx', resource_id: 'energy', quota_scope_id: 'account', operation_namespace: 'energy',
  resource_profile_version: 'merx.energy-purchase.v1-draft.1', resource_profile_hash: MERX_ENERGY_V1.hash,
  policy_version: 'owner-passkey-v1', account_required_actions: ['energy.purchase'],
});

test('Energy descriptor is package-owned, canonical and pinned', () => {
  if (existsSync(descriptorPath)) assert.equal(readFileSync(descriptorPath, 'utf8').trim(), MERX_ENERGY_DESCRIPTOR_JSON);
  assert.equal(MERX_ENERGY_V1.hash, 'sha256:e1c5106dc710ce0ba3d846f3cb376358eb858c35adfbac906f0ff58f3a6451fa');
  assert.equal(MERX_SANDBOX_V1.hash, 'sha256:dc6f6409a47da2a97ea7b4ace313985d7fcd4c6b8459a59ea06b014de304a175');
  assert.equal(validateResourceRegistration(registration).profile, MERX_ENERGY_V1);
  if (vectors) assert.equal(vectors.descriptor_hash, MERX_ENERGY_V1.hash);
});

test('Energy action accepts exact canonical values', () => {
  assert.deepEqual(normalizeProfileAction(permission, MERX_ENERGY_V1), permission);
  assert.deepEqual(normalizeProfileGrant({ permissions: [permission], grant_limit: 1,
    grant_expires_at_ms: parameters.quote_expires_at_ms }, MERX_ENERGY_V1), {
    permissions: [permission], grant_limit: 1, grant_expires_at_ms: parameters.quote_expires_at_ms,
  });
});

test('Energy action rejects checksum, SUN, fee and shape violations', () => {
  const invalid = [
    { recipient: `${recipient.slice(0, -1)}n` },
    { resource_cost_sun: '01' },
    { resource_cost_sun: '+1' },
    { resource_cost_sun: '1.0' },
    { resource_cost_sun: '1\n' },
    { resource_cost_sun: `${Number.MAX_SAFE_INTEGER + 1}` },
    { activation_fee_cap_sun: '9007199254740991', max_total_debit_sun: '9007199255845991' },
    { platform_fee_sun: '1', max_total_debit_sun: '1205001' },
    { network_fee_cap_sun: '1', max_total_debit_sun: '1205001' },
    { max_total_debit_sun: '1205001' },
    { quote_id: '123e4567-e89b-12d3-a456-426614174000' },
    { quote_expires_at_ms: 8_640_000_000_000_001 },
    { amount: 64_999 },
    { duration_sec: 3_599 },
  ];
  for (const replacement of invalid) {
    assert.throws(() => normalizeProfileAction({ action: permission.action,
      parameters: { ...parameters, ...replacement } }, MERX_ENERGY_V1), TypeError);
  }
  assert.throws(() => normalizeProfileAction({ action: permission.action,
    parameters: { ...parameters, extra: true } }, MERX_ENERGY_V1), TypeError);
});

test('Energy grant is one exact permission and expires by the quote', () => {
  assert.throws(() => normalizeProfileGrant({ permissions: [permission], grant_limit: 2,
    grant_expires_at_ms: parameters.quote_expires_at_ms }, MERX_ENERGY_V1), TypeError);
  assert.throws(() => normalizeProfileGrant({ permissions: [permission, { action: 'prices.read' }], grant_limit: 1,
    grant_expires_at_ms: parameters.quote_expires_at_ms }, MERX_ENERGY_V1), TypeError);
  assert.throws(() => normalizeProfileGrant({ permissions: [permission], grant_limit: 1,
    grant_expires_at_ms: parameters.quote_expires_at_ms + 1 }, MERX_ENERGY_V1), TypeError);
});

test('profile selection rejects unknown hashes, environments and cross-profile actions', () => {
  for (const replacement of [
    { environment: 'sandbox' },
    { resource_profile_hash: `sha256:${'0'.repeat(64)}` },
    { resource_profile_version: 'unknown' },
  ]) assert.throws(() => validateResourceRegistration({ ...registration, ...replacement }), TypeError);
  assert.throws(() => normalizeProfileAction(permission, MERX_SANDBOX_V1), TypeError);
  assert.throws(() => normalizeProfileGrant({ permissions: [permission], grant_limit: 1,
    grant_expires_at_ms: parameters.quote_expires_at_ms }, { ...MERX_ENERGY_V1 }), TypeError);
  assert.throws(() => normalizeProfileAction({ action: 'sandbox.execute', parameters: {
    resource: 'ENERGY', amount: 65_000, duration: 3_600,
  } }, MERX_ENERGY_V1), TypeError);
});

test('Energy context binds the exact production registration and current account', () => {
  const context = {
    protocol_version: '0.1.0-draft.2', resource_profile_version: MERX_ENERGY_V1.profile,
    resource_profile_hash: MERX_ENERGY_V1.hash, issuer: registration.issuer, audience: registration.audience,
    environment: 'production', tenant_id: registration.tenant_id, resource_id: registration.resource_id,
    quota_scope_id: registration.quota_scope_id, operation_namespace: registration.operation_namespace,
    scoped_subject: 'owner-1', operation_id: 'operation-1', grant_id: 'grant-1', grant_version: 1,
    policy_version: registration.policy_version, agent_key_thumbprint: Buffer.alloc(32).toString('base64url'),
    consent_hash: `sha256:${'0'.repeat(64)}`, action_hash: actionHash(permission),
    account_binding_id: 'binding-1', account_binding_version: 1, action: 'energy.purchase',
  };
  assert.doesNotThrow(() => validateBoundIntent(context, permission, registration));
  assert.equal(canonicalAction(permission), '{"action":"energy.purchase","parameters":{"activation_fee_cap_sun":"100000","amount":65000,"duration_sec":3600,"execution_provider":"powersun-merx","max_total_debit_sun":"1205000","network":"tron-mainnet","network_fee_cap_sun":"0","platform_fee_sun":"0","quote_expires_at_ms":1800000000000,"quote_id":"123e4567-e89b-42d3-a456-426614174000","recipient":"TA4Wt1DUCqz6YegbnsmqsWC5uUfbdBqPxm","resource":"ENERGY","resource_cost_sun":"1105000"}}');
  assert.equal(actionHash(permission), 'sha256:5f77df78ddb09fb920b926a6ae6a84cf0135e17d5780994f08f8a2c9524a442d');
  if (vectors) {
    assert.deepEqual(vectors.valid_action, permission);
    assert.equal(vectors.canonical_action, canonicalAction(permission));
    assert.equal(vectors.action_hash, actionHash(permission));
    assert.deepEqual(normalizeProfileGrant(vectors.grant, MERX_ENERGY_V1), vectors.grant);
  }
  assert.throws(() => validateBoundIntent({ ...context, account_binding_id: null, account_binding_version: null }, permission, registration), TypeError);
  assert.throws(() => validateBoundIntent({ ...context, environment: 'sandbox' }, permission, registration), TypeError);
});
