/** Pinned service assertions. These never turn a request proof into authority. */
import { compactVerify, importJWK } from 'jose';
import { actionHash, canonicalContext, intentHash, parseStrictJson, validateBoundIntent } from './context.mjs';

const MAX_TIME = 8_640_000_000_000_000;
const ID = /^[A-Za-z0-9._:-]{1,128}$/;
const TYPES = { snapshot: 'atum-grant-status+jwt', admission: 'atum-admission+jwt' };
const PROFILES = { snapshot: 'atum-grant-status-v1-draft.1', admission: 'atum-admission-v1-draft.1' };
const DENIALS = ['grant_not_active', 'grant_expired', 'account_not_bound', 'action_not_permitted', 'parameter_limit', 'evidence_insufficient'];
const OMIT_TEMPLATE = new Set(['operation_id', 'action', 'action_hash']);
const REGISTRATION = ['issuer', 'audience', 'environment', 'tenant_id', 'resource_id', 'quota_scope_id', 'operation_namespace', 'resource_profile_version', 'resource_profile_hash', 'policy_version', 'account_required_actions'];

export class AuthorityError extends Error {
  constructor(code) { super(code); this.name = 'AuthorityError'; this.code = code; }
}
const fail = (code = 'invalid_proof') => { throw new AuthorityError(code); };
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
function exact(value, keys) { if (!plain(value) || Object.keys(value).length !== keys.length || keys.some(k => !Object.hasOwn(value, k))) fail(); }
function id(value) { if (typeof value !== 'string' || !ID.test(value) || /\s/.test(value)) fail(); return value; }
function integer(value, minimum = 0, maximum = MAX_TIME) { if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail(); return value; }
function plus(value, amount) { if (value > MAX_TIME - amount) fail(); return value + amount; }
function frozen(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(frozen));
  if (plain(value)) return Object.freeze(Object.fromEntries(Object.entries(value).map(([k, v]) => [k, frozen(v)])));
  return value;
}
const templateOf = context => Object.fromEntries(Object.entries(context).filter(([k]) => !OMIT_TEMPLATE.has(k)));
function canonicalB64(value, max, exactLength) {
  if (typeof value !== 'string' || !value.length || /[^A-Za-z0-9_-]/.test(value) || value.length > Math.ceil(max * 4 / 3)) fail();
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length > max || (exactLength !== undefined && decoded.length !== exactLength) || decoded.toString('base64url') !== value) fail();
  return decoded;
}
function sample(clock, previous) {
  try {
    const value = clock(); exact(value, ['now_ms', 'uncertainty_ms', 'healthy']);
    const now = integer(value.now_ms); const uncertainty = integer(value.uncertainty_ms, 0, 1000);
    if (value.healthy !== true || now < uncertainty || now > MAX_TIME - uncertainty || (previous !== undefined && now < previous)) fail();
    return { now, lower: now - uncertainty, upper: now + uncertainty };
  } catch { fail('temporarily_unavailable'); }
}
function bound(context, action, registration) {
  try {
    const copied = structuredClone(context); const request = structuredClone(action);
    validateBoundIntent(copied, request, registration);
    return { context: frozen(copied), action: frozen(request) };
  } catch { fail('invalid_request'); }
}
function validRegistration(value) {
  exact(value, REGISTRATION);
  const action = { action: 'prices.read', parameters: {} };
  const context = { ...value, protocol_version: '0.1.0-draft.2', scoped_subject: 'validation', operation_id: 'validation', grant_id: 'validation', grant_version: 1, agent_key_thumbprint: Buffer.alloc(32).toString('base64url'), consent_hash: `sha256:${'0'.repeat(64)}`, account_binding_id: 'validation', account_binding_version: 1, action: action.action, action_hash: actionHash(action) };
  delete context.account_required_actions;
  bound(context, action, value);
  return frozen(structuredClone(value));
}
function validPolicy(value) {
  if (value === null) return null;
  exact(value, ['profile', 'policy_version', 'source_profiles', 'max_age_ms']);
  id(value.profile); id(value.policy_version); integer(value.max_age_ms, 1, 86400000);
  if (!Array.isArray(value.source_profiles) || !value.source_profiles.length || value.source_profiles.length > 16 || new Set(value.source_profiles).size !== value.source_profiles.length) fail();
  value.source_profiles.forEach(id);
  return frozen(structuredClone(value));
}
function validGrant(value, registration) {
  exact(value, ['template', 'client_id', 'grant_expires_at_ms', 'grant_limit', 'permissions']);
  id(value.client_id); integer(value.grant_expires_at_ms); integer(value.grant_limit, 0, 1000000000);
  const dummy = { action: 'prices.read', parameters: {} };
  if (!plain(value.template) || [...OMIT_TEMPLATE].some(k => Object.hasOwn(value.template, k))) fail();
  const validationContext = { ...value.template, operation_id: 'validation', action: dummy.action, action_hash: actionHash(dummy) };
  try {
    canonicalContext(validationContext);
    validateBoundIntent({ ...validationContext, account_binding_id: 'validation', account_binding_version: 1 }, dummy, registration);
  } catch { fail(); }
  if (!Array.isArray(value.permissions) || !value.permissions.length || value.permissions.length > 3 || new Set(value.permissions.map(p => p?.action)).size !== value.permissions.length) fail();
  for (const permission of value.permissions) {
    if (value.template.account_binding_id === null && registration.account_required_actions.includes(permission?.action)) fail();
    if (permission?.action === 'prices.read') exact(permission, ['action']);
    else {
      exact(permission, ['action', 'max_amount', 'max_duration', 'max_price_sun']);
      if (!['order.preview', 'sandbox.execute'].includes(permission.action)) fail();
      integer(permission.max_amount, 1, 1000000000); integer(permission.max_duration, 1, 2592000);
      if (permission.max_price_sun !== null) integer(permission.max_price_sun, 1, 1000000000000);
    }
  }
  return value;
}
function evidenceShape(value) {
  if (value === null) return null;
  exact(value, ['assertion_id', 'profile', 'policy_version', 'source_profile', 'evaluation_mode', 'result', 'observed_at_ms', 'evaluated_at_ms', 'issued_at_ms', 'valid_until_ms']);
  ['assertion_id', 'profile', 'policy_version', 'source_profile'].forEach(k => id(value[k]));
  if (!['server_recomputed', 'synthetic'].includes(value.evaluation_mode) || !['passed', 'failed', 'insufficient_data', 'not_performed'].includes(value.result)) fail();
  ['observed_at_ms', 'evaluated_at_ms', 'issued_at_ms', 'valid_until_ms'].forEach(k => integer(value[k]));
  if (value.observed_at_ms > value.evaluated_at_ms || value.evaluated_at_ms > value.issued_at_ms || value.issued_at_ms >= value.valid_until_ms) fail();
  return value;
}
function checkEvidence(value, policy, time) {
  evidenceShape(value);
  if (value !== null && value.issued_at_ms > time.lower) fail();
  if (policy !== null && (value === null || value.profile !== policy.profile || value.policy_version !== policy.policy_version || !policy.source_profiles.includes(value.source_profile) || value.result !== 'passed' || time.upper >= value.valid_until_ms || time.upper - value.observed_at_ms > policy.max_age_ms)) fail();
}
function decode(token, kind) {
  if (typeof token !== 'string' || token.length > 32768 || /[^A-Za-z0-9_.-]/.test(token)) fail();
  const parts = token.split('.'); if (parts.length !== 3) fail();
  const header = parseStrictJson(canonicalB64(parts[0], 2048), 2048);
  const claims = parseStrictJson(canonicalB64(parts[1], 24000), 24000);
  canonicalB64(parts[2], 64, 64);
  exact(header, ['alg', 'typ', 'kid']);
  if (header.alg !== 'ES256' || header.typ !== TYPES[kind]) fail(); id(header.kid);
  exact(claims, ['iss', 'aud', 'sub', 'iat', 'exp', 'jti', 'profile', 'data']);
  id(claims.jti); id(claims.sub);
  if (claims.profile !== PROFILES[kind]) fail();
  integer(claims.iat); integer(claims.exp); if (claims.exp <= claims.iat) fail();
  return { header, claims };
}
function snapshotData(claims, input, registration, policy, time, clientId) {
  const data = claims.data;
  exact(data, ['grant', 'status', 'evidence', 'issued_at_ms', 'valid_until_ms']);
  validGrant(data.grant, registration); integer(data.issued_at_ms); integer(data.valid_until_ms);
  if (data.status !== 'active' || data.grant.client_id !== clientId || data.issued_at_ms > time.upper) fail();
  const expectedTemplate = templateOf(input.context);
  if (Object.keys(expectedTemplate).some(k => expectedTemplate[k] !== data.grant.template[k])) fail();
  checkEvidence(data.evidence, policy, time);
  const cap = Math.min(plus(data.issued_at_ms, 30000), data.grant.grant_expires_at_ms, policy === null ? MAX_TIME : data.evidence.valid_until_ms);
  if (data.valid_until_ms !== cap || cap <= data.issued_at_ms || claims.iat !== Math.floor(data.issued_at_ms / 1000) || claims.exp !== Math.ceil(cap / 1000)) fail();
  if (time.upper >= cap) fail('expired');
  return frozen({ ...data, authorization_effect: 'reservation_only', requires_admission: true });
}
function admissionData(claims, input, registration, time, mode) {
  const data = claims.data;
  exact(data, ['context', 'intent_hash', 'admission_id', 'decision', 'reason', 'evaluated_at_ms', 'evaluated_uncertainty_ms', 'grant_expires_at_ms', 'acceptance_expires_at_ms', 'first_submit_expires_at_ms', 'evidence']);
  try { validateBoundIntent(data.context, input.action, registration); } catch { fail(); }
  if (canonicalContext(data.context) !== canonicalContext(input.context) || data.intent_hash !== intentHash(input.context) || claims.jti !== id(data.admission_id)) fail();
  const evaluated = integer(data.evaluated_at_ms); const uncertainty = integer(data.evaluated_uncertainty_ms, 0, 1000); const expiry = integer(data.grant_expires_at_ms);
  if (evaluated < uncertainty || evaluated > time.upper || claims.iat !== Math.floor(evaluated / 1000)) fail();
  evidenceShape(data.evidence);
  if (data.evidence !== null && data.evidence.issued_at_ms > evaluated - uncertainty) fail();
  let authority = 'none';
  if (data.decision === 'admitted') {
    const acceptance = integer(data.acceptance_expires_at_ms); const first = integer(data.first_submit_expires_at_ms);
    if (data.reason !== 'admitted' || acceptance !== Math.min(plus(evaluated, 10000), expiry) || first !== Math.min(plus(evaluated, 30000), expiry) || acceptance <= evaluated + uncertainty || first <= evaluated + uncertainty || claims.exp !== Math.ceil(first / 1000)) fail();
    if (mode === 'accept') { if (time.upper >= acceptance) fail('expired'); authority = 'admission'; }
  } else if (data.decision === 'denied') {
    if (!DENIALS.includes(data.reason) || data.acceptance_expires_at_ms !== null || data.first_submit_expires_at_ms !== null || claims.exp !== Math.ceil(plus(evaluated, 300000) / 1000)) fail();
    if (mode === 'accept' && time.upper >= evaluated + 300000) fail('expired');
  } else fail();
  return frozen({ ...data, authorization_effect: authority, ...(mode === 'inspect' ? { historical: true } : {}) });
}

export async function createAuthorityVerifier(config) {
  let registration; let policy; let clock; let jwks;
  try {
    exact(config, ['registration', 'evidencePolicy', 'issuerKeys', 'clock']);
    registration = validRegistration(config.registration); policy = validPolicy(config.evidencePolicy);
    clock = config.clock; if (typeof clock !== 'function' || !plain(config.issuerKeys)) fail();
    jwks = structuredClone(config.issuerKeys);
    if (!Object.keys(jwks).length || Object.keys(jwks).length > 8) fail();
    for (const [kid, jwk] of Object.entries(jwks)) {
      id(kid); exact(jwk, ['kty', 'crv', 'x', 'y']);
      if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') fail();
      canonicalB64(jwk.x, 32, 32); canonicalB64(jwk.y, 32, 32);
    }
  } catch { throw new TypeError('invalid authority config'); }
  const keys = new Map();
  try { for (const [kid, jwk] of Object.entries(jwks)) keys.set(kid, await importJWK(jwk, 'ES256')); } catch { throw new TypeError('invalid authority config'); }

  async function verify(token, kind, context, actionRequest, clientId, mode) {
    try {
      // Capture all caller-owned objects before the first asynchronous crypto wait.
      const input = bound(context, actionRequest, registration);
      if (kind === 'snapshot') { try { id(clientId); } catch { fail('invalid_request'); } }
      if (kind === 'admission' && !['accept', 'inspect'].includes(mode)) fail('invalid_request');
      const before = sample(clock); const decoded = decode(token, kind); const key = keys.get(decoded.header.kid);
      if (!key) fail();
      const { claims } = decoded;
      if (claims.iss !== registration.issuer || claims.aud !== registration.audience || claims.sub !== input.context.scoped_subject) fail();
      await compactVerify(token, key, { algorithms: ['ES256'] });
      const after = sample(clock, before.now);
      return kind === 'snapshot' ? snapshotData(claims, input, registration, policy, after, clientId) : admissionData(claims, input, registration, after, mode);
    } catch (error) {
      if (error instanceof AuthorityError) throw error;
      fail();
    }
  }
  return Object.freeze({
    verifyGrantSnapshot: (token, context, actionRequest, clientId) => verify(token, 'snapshot', context, actionRequest, clientId),
    verifyAdmission: (token, context, actionRequest, options) => {
      try { exact(options, ['mode']); } catch { return Promise.reject(new AuthorityError('invalid_request')); }
      return verify(token, 'admission', context, actionRequest, undefined, options.mode);
    },
  });
}
