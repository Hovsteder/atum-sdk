import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  actionHash,
  canonicalAction,
  canonicalContext,
  intentHash,
  operationKey,
  parseStrictJson,
  quotaKey,
  validateBoundIntent,
} from '../src/context.mjs';

const vectors = JSON.parse(await readFile(new URL('../../../candidate/vectors.json', import.meta.url)));

test('matches every published action golden vector', () => {
  for (const vector of vectors.actions) {
    assert.equal(canonicalAction(vector.request), vector.canonical, vector.name);
    assert.equal(actionHash(vector.request), vector.action_hash, vector.name);
  }
});

test('matches every published context hash and tuple vector', () => {
  for (const vector of vectors.contexts) {
    assert.equal(intentHash(vector.context), vector.intent_hash, vector.name);
    assert.deepEqual(operationKey(vector.context), vector.operation_key, vector.name);
    assert.deepEqual(quotaKey(vector.context), vector.quota_key, vector.name);
    assert.doesNotThrow(() => validateBoundIntent(vector.context, vector.action_request, vector.registration), vector.name);
    assert.equal(canonicalContext(vector.context), JSON.stringify(vector.context, Object.keys(vector.context).sort()), vector.name);
  }
});

test('rejects malformed wire JSON before parsing can discard security-relevant input', () => {
  const badInputs = [
    '{"x":1,"x":2}',
    '{"x":1,"\\u0078":2}',
    '{"x":[{"a":1,"\\u0061":2}]}',
    '{/* comment */"x":1}',
    '{"x":1,}',
    '{"__proto__":1}',
    '{"constructor":1}',
    '{"prototype":1}',
    '[1]',
    '{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{"k":{"l":{"m":1}}}}}}}}}}}}}',
    '{"a":[[[[[[[[[[[[0]]]]]]]]]]]]}',
    '{"x":1e400}',
    '{"x":"line\nbreak"}',
    new Uint8Array([0x7b, 0x22, 0x78, 0x22, 0x3a, 0xc3, 0x28, 0x7d]),
  ];
  for (const input of badInputs) assert.throws(() => parseStrictJson(input), TypeError);
});

test('counts UTF-8 bytes and accepts JSON whitespace at newline boundaries', () => {
  assert.deepEqual(parseStrictJson('{\n  "x": 1\n}'), { x: 1 });
  assert.deepEqual(parseStrictJson('{"x":1}', 7), { x: 1 });
  assert.throws(() => parseStrictJson('{"x":1}', 6), TypeError);
  const utf8 = new TextEncoder().encode('{"x":"é"}');
  assert.deepEqual(parseStrictJson(utf8, utf8.byteLength), { x: 'é' });
  assert.throws(() => parseStrictJson(utf8, utf8.byteLength - 1), TypeError);
  assert.throws(() => parseStrictJson(' '.repeat(100_000)), TypeError);
  assert.throws(() => parseStrictJson('\uFEFF{"x":1}'), TypeError);
  assert.throws(() => parseStrictJson(new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d])), TypeError);
});

test('allows exactly twelve nested containers and rejects thirteen', () => {
  const twelve = `{"a":${'['.repeat(11)}0${']'.repeat(11)}}`;
  const thirteen = `{"a":${'['.repeat(12)}0${']'.repeat(12)}}`;
  assert.deepEqual(parseStrictJson(twelve), JSON.parse(twelve));
  assert.throws(() => parseStrictJson(thirteen), TypeError);
});

test('stops a 10,000-level array before recursive parser exhaustion', () => {
  const tooDeep = `{"a":${'['.repeat(10_000)}0${']'.repeat(10_000)}}`;
  assert.throws(() => parseStrictJson(tooDeep), TypeError);
});

test('accepts integral JSON numeric spellings but rejects boolean, fractional, and unsafe values', () => {
  const action = { action: 'order.preview', parameters: { amount: 1e0, duration: 30.0, resource: 'ENERGY' } };
  assert.equal(canonicalAction(action), '{"action":"order.preview","parameters":{"amount":1,"duration":30,"resource":"ENERGY"}}');
  for (const amount of [true, 1.5, Number.MAX_SAFE_INTEGER + 1, Infinity]) {
    assert.throws(() => canonicalAction({ action: 'order.preview', parameters: { amount, duration: 1, resource: 'ENERGY' } }), TypeError);
  }
});

test('rejects malformed registrations and account-required action binding', () => {
  const vector = vectors.contexts[0];
  const duplicateActions = structuredClone(vector.registration);
  duplicateActions.account_required_actions = ['prices.read', 'prices.read'];
  assert.throws(() => validateBoundIntent(vector.context, vector.action_request, duplicateActions), TypeError);
  const requiresAccount = structuredClone(vector.registration);
  requiresAccount.account_required_actions = ['prices.read'];
  assert.throws(() => validateBoundIntent(vector.context, vector.action_request, requiresAccount), TypeError);
  const wrongRegistration = structuredClone(vector.registration);
  wrongRegistration.policy_version = 'different';
  assert.throws(() => validateBoundIntent(vector.context, vector.action_request, wrongRegistration), TypeError);
});

test('rejects final newlines in every regex-constrained context field', () => {
  const context = structuredClone(vectors.contexts[1].context);
  const fields = [
    'issuer', 'audience', 'tenant_id', 'resource_id', 'quota_scope_id', 'operation_namespace',
    'scoped_subject', 'operation_id', 'grant_id', 'policy_version', 'agent_key_thumbprint',
    'consent_hash', 'action_hash', 'account_binding_id',
  ];
  for (const field of fields) {
    const mutated = structuredClone(context);
    mutated[field] += '\n';
    assert.throws(() => canonicalContext(mutated), TypeError, field);
  }
});
