import { intentHash } from '@atum/verification/context';

import { AgentError } from './key.mjs';
import { createProtectedRequestSigner } from './resource-proof.mjs';
import { createProtectedResourceTransport } from './resource-transport.mjs';
import { snapshotData } from './strict.mjs';

const ID = /^[A-Za-z0-9_-]{43}$/;
const HASH = /^sha256:[0-9a-f]{64}$/;
const ENERGY_ORDER_ID = /[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/;
const POSITIVE_SUN = /[1-9][0-9]*/;
const MAX_SAFE_SUN = 9_007_199_254_740_991n;
const PROFILE = 'merx-atum-resource-v1-draft.1';
const ERROR_STATUS = Object.freeze({ invalid_request: 400, invalid_proof: 401, grant_not_active: 403, forbidden: 403,
  operation_conflict: 409, rate_limited: 429, quota_exceeded: 429, temporarily_unavailable: 503 });
const FINAL = new Set(['succeeded', 'failed', 'rejected', 'expired']);
const PENDING = new Set(['prepared', 'accepted', 'submitting', 'unknown']);

export class ResourceInvocationError extends Error {
  constructor(code, status = null) { super('resource invocation failed'); Object.defineProperty(this, 'name', { value: 'ResourceInvocationError' }); Object.defineProperty(this, 'code', { value: code, enumerable: true }); Object.defineProperty(this, 'status', { value: status, enumerable: true }); }
}
const unavailable = () => new ResourceInvocationError('temporarily_unavailable');
const invalid = () => new ResourceInvocationError('invalid_request', 400);
function exact(value, fields) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field)); }
function full(value, pattern) { if (typeof value !== 'string') return false; const matched = pattern.exec(value); return matched !== null && matched[0] === value; }
function freeze(value) { if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); } return value; }
function deadline(value) { const remaining = Math.floor(value - performance.now()); if (remaining < 1) throw unavailable(); return remaining; }
function config(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError('invalid config');
  const allowed = new Set(['registration', 'key', 'endpoint', 'clock', 'tls', 'timeoutMs', 'maxConcurrent', 'maxOperations']); const keys = Reflect.ownKeys(value);
  if (keys.some(key => typeof key !== 'string' || !allowed.has(key)) || !['registration', 'key', 'endpoint', 'clock'].every(key => Object.hasOwn(value, key)) || typeof value.clock !== 'function') throw new TypeError('invalid config');
  let registration; let endpoint; try { registration = snapshotData(value.registration); endpoint = snapshotData(value.endpoint); } catch { throw new TypeError('invalid config'); }
  if (!exact(endpoint, ['method', 'url']) || endpoint.method !== 'POST' || typeof endpoint.url !== 'string') throw new TypeError('invalid config');
  let parsed; try { parsed = new URL(endpoint.url); } catch { throw new TypeError('invalid config'); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== '/v1/atum/operations' || parsed.href !== endpoint.url) throw new TypeError('invalid config');
  const timeoutMs = value.timeoutMs ?? 5000; const maxConcurrent = value.maxConcurrent ?? 4; const maxOperations = value.maxOperations ?? 4096;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 5000 || !Number.isSafeInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 16 || !Number.isSafeInteger(maxOperations) || maxOperations < 1 || maxOperations > 65536) throw new TypeError('invalid config');
  const transport = { endpoint, timeoutMs, maxConcurrent }; if (Object.hasOwn(value, 'tls')) transport.tls = value.tls;
  const saved = Object.freeze({ registration, key: value.key, endpoint, clock: value.clock, timeoutMs, maxConcurrent, maxOperations, transport });
  try { createProtectedRequestSigner({ registration, key: saved.key, endpoint, clock: saved.clock, timeoutMs }); } catch { throw new TypeError('invalid config'); }
  return saved;
}
function energyBounds(action) {
  if (action.action !== 'energy.purchase') return null;
  const minimum = action.parameters?.resource_cost_sun; const maximum = action.parameters?.max_total_debit_sun;
  if (!full(minimum, POSITIVE_SUN) || !full(maximum, POSITIVE_SUN)) throw invalid();
  const lower = BigInt(minimum); const upper = BigInt(maximum);
  if (lower > MAX_SAFE_SUN || upper > MAX_SAFE_SUN || lower > upper) throw invalid();
  return Object.freeze({ lower, upper });
}
function energyResult(value, bounds) {
  if (!exact(value, ['order_id', 'status', 'charged_sun']) || !full(value.order_id, ENERGY_ORDER_ID)
      || value.status !== 'delivered' || !full(value.charged_sun, POSITIVE_SUN)) return false;
  const charged = BigInt(value.charged_sun);
  return charged <= MAX_SAFE_SUN && charged >= bounds.lower && charged <= bounds.upper;
}
function response(response, expected) {
  if (response.status !== 200 && response.status !== 202) {
    const code = response.body?.error; if (!exact(response.body, ['error']) || typeof code !== 'string' || ERROR_STATUS[code] !== response.status) throw unavailable();
    if (code === 'invalid_proof' && response.authenticate !== 'DPoP error="invalid_proof", algs="ES256"') throw unavailable();
    throw new ResourceInvocationError(code, response.status);
  }
  const value = response.body;
  if (!exact(value, ['profile', 'operation_id', 'action_hash', 'intent_hash', 'state', 'result']) || value.profile !== PROFILE || value.operation_id !== expected.id || value.action_hash !== expected.actionHash || value.intent_hash !== expected.intentHash || !HASH.test(value.action_hash) || !HASH.test(value.intent_hash)) throw unavailable();
  const final = FINAL.has(value.state); const pending = PENDING.has(value.state);
  if ((!final && !pending) || (final ? response.status !== 200 : response.status !== 202) || (value.state !== 'succeeded' && value.result !== null)) throw unavailable();
  if (value.state === 'succeeded' && value.result === null) throw unavailable();
  if (value.state === 'succeeded' && expected.action === 'sandbox.execute' && (!exact(value.result, ['simulation', 'operationId']) || value.result.simulation !== true || value.result.operationId !== expected.id)) throw unavailable();
  if (value.state === 'succeeded' && expected.action === 'energy.purchase' && !energyResult(value.result, expected.energyBounds)) throw unavailable();
  return freeze({ http_status: response.status, ...structuredClone(value) });
}

export function createProtectedResourceClient(rawConfig) {
  const saved = config(rawConfig); const transport = createProtectedResourceTransport(saved.transport); const attempted = new Set(); let closed = false;
  async function invoke(rawInput) {
    if (closed) throw unavailable();
    let input; try { input = snapshotData(rawInput); } catch { throw invalid(); }
    if (!exact(input, ['access_token', 'context', 'action_request'])) throw invalid();
    const context = input.context; const action = input.action_request; const id = context?.operation_id;
    let expected; try {
      if (!ID.test(id ?? '') || !HASH.test(context?.action_hash ?? '') || context.action !== action?.action) throw invalid();
      expected = { id, actionHash: context.action_hash, intentHash: intentHash(context), action: action.action,
        energyBounds: energyBounds(action) };
    } catch { throw invalid(); }
    if (attempted.has(id)) throw new ResourceInvocationError('operation_conflict', 409);
    if (attempted.size >= saved.maxOperations) throw unavailable();
    const until = performance.now() + saved.timeoutMs;
    let signer; try { signer = createProtectedRequestSigner({ registration: saved.registration, key: saved.key, endpoint: saved.endpoint, clock: saved.clock, timeoutMs: deadline(until) }); } catch { throw invalid(); }
    attempted.add(id); let dispatched = false;
    let initial; try { initial = await signer.signChallenge(input); } catch (error) { attempted.delete(id); throw error instanceof AgentError && error.code === 'invalid_request' ? invalid() : unavailable(); }
    if (closed) { attempted.delete(id); throw unavailable(); }
    try {
      dispatched = true; const challenge = await transport.post(initial, until); if (closed) throw unavailable();
      if (challenge.status !== 401 || !exact(challenge.body, ['error']) || challenge.body.error !== 'use_dpop_nonce' || challenge.authenticate !== 'DPoP error="use_dpop_nonce", algs="ES256"' || !ID.test(challenge.nonce ?? '')) {
        if (challenge.status >= 200 && challenge.status < 300) throw unavailable();
        return response(challenge, expected);
      }
      signer = createProtectedRequestSigner({ registration: saved.registration, key: saved.key, endpoint: saved.endpoint, clock: saved.clock, timeoutMs: deadline(until) });
      const continuation = await signer.sign({ ...input, nonce: challenge.nonce });
      if (continuation.body !== initial.body || continuation.authorization !== initial.authorization || closed) throw unavailable();
      const final = response(await transport.post(continuation, until), expected);
      if (closed || deadline(until) < 1) throw unavailable();
      return final;
    } catch (error) { if (!dispatched) attempted.delete(id); throw error instanceof ResourceInvocationError ? error : unavailable(); }
  }
  return Object.freeze({ invoke, async close() { closed = true; await transport.close(); } });
}
