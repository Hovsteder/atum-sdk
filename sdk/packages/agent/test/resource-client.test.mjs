import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { actionHash, intentHash } from '@atum/verification/context';
import { createAgentKey } from '../src/key.mjs';
import { createProtectedResourceClient, ResourceInvocationError } from '../src/resource-client.mjs';
import { publicJwk, resourceExample, signingPorts } from './documentation-fixture.mjs';

const energyVector = JSON.parse(readFileSync(new URL('../../../protocol/resource-profiles/merx.energy-purchase.v1-draft.1.vectors.json', import.meta.url)));

function openssl(dir, ...args) { execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' }); }
function certificates() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'atum-agent-resource-client-'));
  writeFileSync(path.join(dir, 'server.ext'), 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n');
  openssl(dir, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-subj', '/CN=atum-agent-resource-client-ca');
  openssl(dir, 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'server.key', '-out', 'server.csr', '-subj', '/CN=localhost');
  openssl(dir, 'x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'server.pem', '-days', '1', '-extfile', 'server.ext');
  return { dir, ca: readFileSync(path.join(dir, 'ca.pem'), 'utf8'), cert: readFileSync(path.join(dir, 'server.pem')), key: readFileSync(path.join(dir, 'server.key')) };
}
function reply(res, status, value, headers = {}) { const bytes = Buffer.from(JSON.stringify(value)); res.writeHead(status, { 'content-type': 'application/json', 'content-length': String(bytes.length), 'cache-control': 'no-store', ...headers }); res.end(bytes); }

function energyExample(key) {
  const sample = resourceExample(key); const action = structuredClone(energyVector.valid_action);
  action.parameters.quote_expires_at_ms += 1;
  const registration = { ...sample.registration, environment: 'production', operation_namespace: 'energy',
    resource_profile_version: 'merx.energy-purchase.v1-draft.1',
    resource_profile_hash: 'sha256:e1c5106dc710ce0ba3d846f3cb376358eb858c35adfbac906f0ff58f3a6451fa',
    account_required_actions: ['energy.purchase'] };
  const context = { ...sample.context, environment: registration.environment,
    operation_namespace: registration.operation_namespace, resource_profile_version: registration.resource_profile_version,
    resource_profile_hash: registration.resource_profile_hash, action: action.action, action_hash: actionHash(action) };
  return { ...sample, registration, context, action };
}

test('public client performs exactly one nonce continuation and fences attempted operation IDs', async t => {
  const certs = certificates(); let calls = 0;
  const server = https.createServer({ cert: certs.cert, key: certs.key }, async (req, res) => {
    calls += 1; const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks));
    if (body.context.operation_id === Buffer.alloc(32, 7).toString('base64url')) return reply(res, 200, { profile: 'merx-atum-resource-v1-draft.1', operation_id: body.context.operation_id, action_hash: body.context.action_hash, intent_hash: intentHash(body.context), state: 'succeeded', result: { simulation: true, operationId: body.context.operation_id } });
    if (!JSON.parse(Buffer.from(req.headers.dpop.split('.')[1], 'base64url')).nonce) return reply(res, 401, { error: 'use_dpop_nonce' }, { 'dpop-nonce': Buffer.alloc(32, 7).toString('base64url'), 'www-authenticate': 'DPoP error="use_dpop_nonce", algs="ES256"' });
    if (body.context.operation_id === Buffer.alloc(32, 8).toString('base64url')) { res.destroy(); return; }
    if (body.action_request.action === 'prices.read') return reply(res, 200, { profile: 'merx-atum-resource-v1-draft.1', operation_id: body.context.operation_id, action_hash: body.context.action_hash, intent_hash: intentHash(body.context), state: 'succeeded', result: { prices: [] } });
    if (body.context.operation_id === Buffer.alloc(32, 4).toString('base64url')) return reply(res, 202, { profile: 'merx-atum-resource-v1-draft.1', operation_id: body.context.operation_id, action_hash: body.context.action_hash, intent_hash: intentHash(body.context), state: 'unknown', result: null });
    if (body.context.operation_id === Buffer.alloc(32, 5).toString('base64url')) return reply(res, 403, { error: 'grant_not_active' });
    if (body.context.operation_id === Buffer.alloc(32, 6).toString('base64url')) return reply(res, 200, { profile: 'merx-atum-resource-v1-draft.1', operation_id: Buffer.alloc(32, 9).toString('base64url'), action_hash: body.context.action_hash, intent_hash: intentHash(body.context), state: 'succeeded', result: { simulation: true, operationId: body.context.operation_id } });
    return reply(res, 200, { profile: 'merx-atum-resource-v1-draft.1', operation_id: body.context.operation_id, action_hash: body.context.action_hash, intent_hash: intentHash(body.context), state: 'succeeded', result: { simulation: true, operationId: body.context.operation_id } });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); rmSync(certs.dir, { recursive: true, force: true }); });
  const key = await createAgentKey({ publicJwk, sign: signingPorts().signingPort.signEs256IeeeP1363 });
  const sample = resourceExample(key); sample.registration.account_required_actions = ['sandbox.execute']; const id = Buffer.alloc(32, 3).toString('base64url');
  const context = { ...sample.context, operation_id: id }; const action = { action: 'sandbox.execute', parameters: { resource: 'ENERGY', amount: 2, duration: 30, max_price_sun: 9 } };
  context.action = action.action; context.action_hash = actionHash(action);
  const endpoint = { method: 'POST', url: `https://localhost:${server.address().port}/v1/atum/operations` };
  const client = createProtectedResourceClient({ registration: sample.registration, key, endpoint, clock: sample.clock, tls: { ca: certs.ca } });
  const result = await client.invoke({ access_token: sample.accessToken, context, action_request: action });
  assert.equal(result.state, 'succeeded'); assert.equal(result.http_status, 200); assert.equal(calls, 2);
  await assert.rejects(client.invoke({ access_token: sample.accessToken, context, action_request: action }), error => error instanceof ResourceInvocationError && error.code === 'operation_conflict' && error.status === 409);
  const unknown = { ...context, operation_id: Buffer.alloc(32, 4).toString('base64url') };
  const unknownResult = await client.invoke({ access_token: sample.accessToken, context: unknown, action_request: action });
  assert.equal(unknownResult.state, 'unknown');
  await assert.rejects(client.invoke({ access_token: sample.accessToken, context: unknown, action_request: action }), error => error instanceof ResourceInvocationError && error.code === 'operation_conflict');
  const denied = { ...context, operation_id: Buffer.alloc(32, 5).toString('base64url') };
  await assert.rejects(client.invoke({ access_token: sample.accessToken, context: denied, action_request: action }), error => error instanceof ResourceInvocationError && error.code === 'grant_not_active' && error.status === 403);
  const mismatch = { ...context, operation_id: Buffer.alloc(32, 6).toString('base64url') };
  await assert.rejects(client.invoke({ access_token: sample.accessToken, context: mismatch, action_request: action }), error => error instanceof ResourceInvocationError && error.code === 'temporarily_unavailable');
  assert.equal(calls, 8);
  await assert.rejects(client.invoke(null), error => error instanceof ResourceInvocationError && error.code === 'invalid_request');
  const unexpected = { ...context, operation_id: Buffer.alloc(32, 7).toString('base64url') };
  await assert.rejects(client.invoke({ access_token: sample.accessToken, context: unexpected, action_request: action }), { code: 'temporarily_unavailable' });
  assert.equal(calls, 9, 'a 2xx challenge reply cannot become a completed operation');
  const lost = { ...context, operation_id: Buffer.alloc(32, 8).toString('base64url') };
  await assert.rejects(client.invoke({ access_token: sample.accessToken, context: lost, action_request: action }), { code: 'temporarily_unavailable' });
  assert.equal(calls, 11, 'continuation reached the server before response loss');
  await assert.rejects(client.invoke({ access_token: sample.accessToken, context: lost, action_request: action }), { code: 'operation_conflict' });
  assert.equal(calls, 11, 'an ambiguous outcome remains fenced without another HTTP call');
  const prices = { action: 'prices.read', parameters: {} };
  const priceContext = { ...context, action: prices.action, action_hash: actionHash(prices), operation_id: Buffer.alloc(32, 10).toString('base64url') };
  const priceResult = await client.invoke({ access_token: sample.accessToken, context: priceContext, action_request: prices });
  assert.deepEqual(priceResult.result, { prices: [] });
  assert.equal(calls, 13);
  await client.close();
});

test('public Energy client accepts only the exact bounded delivered result and fences every attempted operation', async t => {
  const certs = certificates(); let calls = 0; const outcomes = new Map();
  const server = https.createServer({ cert: certs.cert, key: certs.key }, async (req, res) => {
    calls += 1; const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks));
    if (!JSON.parse(Buffer.from(req.headers.dpop.split('.')[1], 'base64url')).nonce) {
      return reply(res, 401, { error: 'use_dpop_nonce' }, {
        'dpop-nonce': Buffer.alloc(32, 19).toString('base64url'),
        'www-authenticate': 'DPoP error="use_dpop_nonce", algs="ES256"',
      });
    }
    const selected = outcomes.get(body.context.operation_id);
    return reply(res, selected.httpStatus, { profile: 'merx-atum-resource-v1-draft.1',
      operation_id: body.context.operation_id, action_hash: body.context.action_hash,
      intent_hash: intentHash(body.context), state: selected.state, result: selected.result });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); rmSync(certs.dir, { recursive: true, force: true }); });
  const key = await createAgentKey({ publicJwk, sign: signingPorts().signingPort.signEs256IeeeP1363 });
  const sample = energyExample(key);
  const endpoint = { method: 'POST', url: `https://localhost:${server.address().port}/v1/atum/operations` };
  const client = createProtectedResourceClient({ registration: sample.registration, key, endpoint,
    clock: sample.clock, tls: { ca: certs.ca } });
  const delivered = (order_id, charged_sun) => ({ order_id, status: 'delivered', charged_sun });
  const cases = [
    ['lower bound', true, { httpStatus: 200, state: 'succeeded', result: delivered('123e4567-e89b-42d3-a456-426614174000', '1105000') }],
    ['upper bound', true, { httpStatus: 200, state: 'succeeded', result: delivered('223e4567-e89b-42d3-a456-426614174000', '1205000') }],
    ['pending null', true, { httpStatus: 202, state: 'unknown', result: null }],
    ['failed null', true, { httpStatus: 200, state: 'failed', result: null }],
    ['malformed', false, { httpStatus: 200, state: 'succeeded', result: [] }],
    ['extra field', false, { httpStatus: 200, state: 'succeeded', result: { ...delivered('323e4567-e89b-42d3-a456-426614174000', '1105000'), provider_id: 'hidden' } }],
    ['under quote', false, { httpStatus: 200, state: 'succeeded', result: delivered('423e4567-e89b-42d3-a456-426614174000', '1104999') }],
    ['over spend', false, { httpStatus: 200, state: 'succeeded', result: delivered('523e4567-e89b-42d3-a456-426614174000', '1205001') }],
    ['uppercase id', false, { httpStatus: 200, state: 'succeeded', result: delivered('623E4567-E89B-42D3-A456-426614174000', '1105000') }],
    ['wrong uuid version', false, { httpStatus: 200, state: 'succeeded', result: delivered('723e4567-e89b-32d3-a456-426614174000', '1105000') }],
    ['newline id', false, { httpStatus: 200, state: 'succeeded', result: delivered('723e4567-e89b-42d3-a456-426614174000\n', '1105000') }],
    ['wrong status', false, { httpStatus: 200, state: 'succeeded', result: { ...delivered('823e4567-e89b-42d3-a456-426614174000', '1105000'), status: 'pending' } }],
    ['numeric SUN', false, { httpStatus: 200, state: 'succeeded', result: delivered('923e4567-e89b-42d3-a456-426614174000', 1105000) }],
    ['leading-zero SUN', false, { httpStatus: 200, state: 'succeeded', result: delivered('a23e4567-e89b-42d3-a456-426614174000', '01105000') }],
    ['unsafe SUN', false, { httpStatus: 200, state: 'succeeded', result: delivered('b23e4567-e89b-42d3-a456-426614174000', '9007199254740992') }],
    ['newline SUN', false, { httpStatus: 200, state: 'succeeded', result: delivered('c23e4567-e89b-42d3-a456-426614174000', '1105000\n') }],
  ];
  let byte = 20;
  for (const [name, accepted, outcome] of cases) {
    const context = { ...sample.context, operation_id: Buffer.alloc(32, byte++).toString('base64url') };
    const actionRequest = structuredClone(sample.action);
    outcomes.set(context.operation_id, outcome); const input = { access_token: sample.accessToken, context, action_request: actionRequest };
    const pending = client.invoke(input);
    if (name === 'under quote') {
      actionRequest.parameters.resource_cost_sun = '1';
      actionRequest.parameters.max_total_debit_sun = '9007199254740991';
    }
    if (accepted) {
      const result = await pending;
      assert.deepEqual(result.result, outcome.result, name); assert.equal(Object.isFrozen(result.result ?? result), true, name);
    } else {
      await assert.rejects(pending, error => error instanceof ResourceInvocationError && error.code === 'temporarily_unavailable', name);
      const attemptedCalls = calls;
      await assert.rejects(client.invoke(input), error => error instanceof ResourceInvocationError && error.code === 'operation_conflict', `${name} retry`);
      assert.equal(calls, attemptedCalls, `${name} retry must not issue HTTP`);
    }
  }
  assert.equal(calls, cases.length * 2);
  await client.close();
});

test('reserves a local operation before signing and releases it without network on close', async () => {
  let release; const gate = new Promise(resolve => { release = resolve; }); const ports = signingPorts();
  const key = await createAgentKey({ publicJwk, sign: async bytes => { await gate; return ports.signingPort.signEs256IeeeP1363(bytes); } });
  const sample = resourceExample(key); sample.registration.account_required_actions = ['sandbox.execute'];
  const action = { action: 'sandbox.execute', parameters: { resource: 'ENERGY', amount: 2, duration: 30, max_price_sun: 9 } };
  const makeContext = byte => ({ ...sample.context, operation_id: Buffer.alloc(32, byte).toString('base64url'), action: action.action, action_hash: actionHash(action) });
  const client = createProtectedResourceClient({ registration: sample.registration, key,
    endpoint: { method: 'POST', url: 'https://localhost:44443/v1/atum/operations' }, clock: sample.clock, maxOperations: 1 });
  const first = client.invoke({ access_token: sample.accessToken, context: makeContext(12), action_request: action });
  await new Promise(resolve => setImmediate(resolve));
  await assert.rejects(client.invoke({ access_token: sample.accessToken, context: makeContext(12), action_request: action }), error => error instanceof ResourceInvocationError && error.code === 'operation_conflict');
  await assert.rejects(client.invoke({ access_token: sample.accessToken, context: makeContext(13), action_request: action }), error => error instanceof ResourceInvocationError && error.code === 'temporarily_unavailable');
  const closing = client.close(); release(); await assert.rejects(first, error => error instanceof ResourceInvocationError && error.code === 'temporarily_unavailable'); await closing;
});
