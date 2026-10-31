import { createHash } from 'node:crypto';

import { AgentError, agentKeyTimeout, assertAgentKey } from './key.mjs';
import { canonical, snapshotData } from './strict.mjs';
import { createRequestTransport } from './transport.mjs';

const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const MAX_TIME = 8_640_000_000_000_000;
const ID = /^[A-Za-z0-9._:-]{1,128}$/;
const PARTY = /^[A-Za-z0-9:/._-]{1,256}$/;
const UUID4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const B64 = /^[A-Za-z0-9_-]+$/;
const ACTIONS = new Set(['prices.read', 'order.preview', 'sandbox.execute']);
const REGISTRATION_FIELDS = ['issuer', 'audience', 'environment', 'tenant_id', 'resource_id', 'quota_scope_id', 'operation_namespace', 'resource_profile_version', 'resource_profile_hash', 'policy_version', 'account_required_actions'];
const CLIENT_FIELDS = ['client_id', 'flows', 'redirect_uris', 'permissions', 'max_grant_limit', 'max_grant_lifetime_ms'];
const ENDPOINT_FIELDS = ['options_url', 'verify_url', 'par_url', 'authorization_url', 'device_authorization_url', 'token_url'];
const CONFIG_FIELDS = new Set(['registration', 'client', 'endpoints', 'tls', 'key', 'clock', 'timeoutMs', 'maxConcurrent']);

function unavailable() { return new AgentError('temporarily_unavailable'); }
function invalidRequest() { return new AgentError('invalid_request'); }
function invalidConfig() { throw new TypeError('invalid config'); }

function record(value, fields, invalid) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid();
  let prototype; let keys; let descriptors;
  try { prototype = Object.getPrototypeOf(value); keys = Reflect.ownKeys(value); descriptors = Object.getOwnPropertyDescriptors(value); }
  catch { invalid(); }
  if (prototype !== Object.prototype || keys.some(key => typeof key !== 'string' || !fields.has(key))
      || keys.length !== Object.keys(descriptors).length) invalid();
  const result = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) invalid();
    result[key] = descriptor.value;
  }
  return result;
}
function exact(value, fields) { return value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field)); }
function integer(value, lower = 0, upper = MAX_SAFE) { return typeof value === 'number' && Number.isSafeInteger(value) && !Object.is(value, -0) && value >= lower && value <= upper; }
function uuid4(value) { return typeof value === 'string' && UUID4.test(value); }
function id(value) { return typeof value === 'string' && ID.test(value); }
function ascii(value, maximum = 256) { return typeof value === 'string' && value.length > 0 && value.length <= maximum && /^[\x20-\x7e]+$/.test(value); }
function base64(value, length) {
  if (typeof value !== 'string' || !B64.test(value)) return false;
  let bytes;
  try { bytes = Buffer.from(value, 'base64url'); } catch { return false; }
  return bytes.byteLength === length && bytes.toString('base64url') === value;
}
function same(left, right) { try { return canonical(left) === canonical(right); } catch { return false; } }
function digest(domain, value) { return `sha256:${createHash('sha256').update(domain, 'ascii').update(canonical(value), 'utf8').digest('hex')}`; }

function registrationCopy(value) {
  let source;
  try { source = snapshotData(value); } catch { invalidConfig(); }
  if (!exact(source, REGISTRATION_FIELDS)) invalidConfig();
  const result = {};
  for (const field of REGISTRATION_FIELDS.slice(0, -1)) {
    if (!ascii(source[field])) invalidConfig();
    result[field] = source[field];
  }
  if (!PARTY.test(result.issuer) || !PARTY.test(result.audience) || result.environment !== 'sandbox'
      || result.resource_profile_version !== 'v1-draft.1'
      || result.resource_profile_hash !== 'sha256:dc6f6409a47da2a97ea7b4ace313985d7fcd4c6b8459a59ea06b014de304a175'
      || !['tenant_id', 'resource_id', 'quota_scope_id', 'operation_namespace', 'policy_version'].every(field => id(result[field]))) invalidConfig();
  let issuer;
  try { issuer = new URL(result.issuer); } catch { invalidConfig(); }
  if (issuer.protocol !== 'https:' || issuer.username || issuer.password || issuer.search || issuer.hash
      || (result.issuer !== issuer.origin && result.issuer !== issuer.href)) invalidConfig();
  const required = source.account_required_actions;
  if (!Array.isArray(required) || required.some(action => typeof action !== 'string' || !ACTIONS.has(action))
      || new Set(required).size !== required.length) invalidConfig();
  result.account_required_actions = Object.freeze([...required].sort());
  return Object.freeze(result);
}

function clientCopy(value) {
  let source;
  try { source = snapshotData(value); } catch { invalidConfig(); }
  if (!exact(source, CLIENT_FIELDS) || !id(source.client_id)) invalidConfig();
  const flows = Array.isArray(source.flows) ? [...source.flows].sort() : invalidConfig();
  const redirects = Array.isArray(source.redirect_uris) ? [...source.redirect_uris].sort() : invalidConfig();
  const allowed = Array.isArray(source.permissions) ? [...source.permissions].sort() : invalidConfig();
  if (!flows.length || flows.some(flow => flow !== 'authorization_code' && flow !== 'device_code') || new Set(flows).size !== flows.length
      || !redirects.length || redirects.some(uri => !ascii(uri, 512) || !/^https:\/\/[^\s#?]+(?:\/[^\s#?]*)?$/.test(uri)) || new Set(redirects).size !== redirects.length
      || !allowed.length || allowed.some(action => !ACTIONS.has(action)) || new Set(allowed).size !== allowed.length
      || !integer(source.max_grant_limit, 0, 1_000_000_000) || !integer(source.max_grant_lifetime_ms, 1, 3_600_000)) invalidConfig();
  return Object.freeze({ client_id: source.client_id, flows: Object.freeze(flows), redirect_uris: Object.freeze(redirects),
    permissions: Object.freeze(allowed), max_grant_limit: source.max_grant_limit, max_grant_lifetime_ms: source.max_grant_lifetime_ms });
}

function endpointsCopy(value, issuer) {
  let source;
  try { source = snapshotData(value); } catch { invalidConfig(); }
  if (!exact(source, ENDPOINT_FIELDS)) invalidConfig();
  const origin = new URL(issuer).origin; const result = {};
  for (const field of ENDPOINT_FIELDS) {
    let parsed;
    try { parsed = new URL(source[field]); } catch { invalidConfig(); }
    if (typeof source[field] !== 'string' || parsed.protocol !== 'https:' || parsed.origin !== origin || parsed.username || parsed.password
        || parsed.search || parsed.hash || parsed.href !== source[field]) invalidConfig();
    result[field] = parsed.href;
  }
  return Object.freeze(result);
}

function configCopy(value) {
  const source = record(value, CONFIG_FIELDS, invalidConfig);
  if (!['registration', 'client', 'endpoints', 'tls', 'key', 'clock'].every(field => Object.hasOwn(source, field))
      || typeof source.clock !== 'function') invalidConfig();
  const registration = registrationCopy(source.registration); const client = clientCopy(source.client);
  const endpoints = endpointsCopy(source.endpoints, registration.issuer);
  let tls;
  try { tls = snapshotData(source.tls); } catch { invalidConfig(); }
  if (!exact(tls, ['ca']) || typeof tls.ca !== 'string' || !tls.ca.length) invalidConfig();
  let key;
  try { key = assertAgentKey(source.key); } catch { invalidConfig(); }
  const timeoutMs = Object.hasOwn(source, 'timeoutMs') ? source.timeoutMs : 5000;
  const maxConcurrent = Object.hasOwn(source, 'maxConcurrent') ? source.maxConcurrent : 4;
  if (!integer(timeoutMs, 1, 5000) || !integer(maxConcurrent, 1, 16)) invalidConfig();
  return Object.freeze({ registration, client, endpoints, tls: Object.freeze({ ca: tls.ca }), key, clock: source.clock, timeoutMs, maxConcurrent });
}

function permission(value, allowed) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || typeof value.action !== 'string'
      || !ACTIONS.has(value.action) || !allowed.includes(value.action)) throw invalidRequest();
  if (value.action === 'prices.read') {
    if (!exact(value, ['action'])) throw invalidRequest();
    return Object.freeze({ action: value.action });
  }
  if (!exact(value, ['action', 'max_amount', 'max_duration', 'max_price_sun'])
      || !integer(value.max_amount, 1, 1_000_000_000) || !integer(value.max_duration, 1, 2_592_000)
      || (value.max_price_sun !== null && !integer(value.max_price_sun, 1, 1_000_000_000_000))) throw invalidRequest();
  return Object.freeze({ action: value.action, max_amount: value.max_amount, max_duration: value.max_duration, max_price_sun: value.max_price_sun });
}

function intentCopy(value, saved, clock) {
  let source;
  try { source = snapshotData(value); } catch { throw invalidRequest(); }
  const common = ['flow', 'permissions', 'grant_limit', 'grant_expires_at_ms'];
  const fields = source.flow === 'authorization_code' ? [...common, 'redirect_uri', 'code_challenge', 'state'] : common;
  if (!exact(source, fields) || !saved.client.flows.includes(source.flow) || !Array.isArray(source.permissions)
      || source.permissions.length < 1 || source.permissions.length > 3 || !integer(source.grant_limit, 0, saved.client.max_grant_limit)
      || !integer(source.grant_expires_at_ms, 0, MAX_TIME) || source.grant_expires_at_ms <= clock.upper
      || source.grant_expires_at_ms > clock.now + saved.client.max_grant_lifetime_ms) throw invalidRequest();
  const permissions = source.permissions.map(item => permission(item, saved.client.permissions))
    .sort((left, right) => left.action < right.action ? -1 : left.action > right.action ? 1 : 0);
  if (new Set(permissions.map(item => item.action)).size !== permissions.length) throw invalidRequest();
  let code = null;
  if (source.flow === 'authorization_code') {
    if (!saved.client.redirect_uris.includes(source.redirect_uri) || !base64(source.code_challenge, 32)
        || typeof source.state !== 'string' || source.state.length < 22 || source.state.length > 128 || !B64.test(source.state)) throw invalidRequest();
    code = Object.freeze({ redirect_uri: source.redirect_uri, code_challenge: source.code_challenge, code_challenge_method: 'S256', state: source.state });
  }
  const detail = Object.freeze({ type: 'atum', permissions: Object.freeze(permissions), grant_limit: source.grant_limit, grant_expires_at_ms: source.grant_expires_at_ms });
  const optionsBody = Object.freeze({ flow: source.flow, client_id: saved.client.client_id, resource: saved.registration.audience,
    authorization_details: Object.freeze([detail]), code, agent_jwk: saved.key.publicJwk });
  return Object.freeze({ optionsBody, detail, code });
}

function clockSample(saved, previous) {
  let value;
  try { value = snapshotData(saved.clock()); } catch { throw unavailable(); }
  if (!exact(value, ['now_ms', 'uncertainty_ms', 'healthy']) || value.healthy !== true || !integer(value.now_ms, 0, MAX_TIME)
      || !integer(value.uncertainty_ms, 0, 1000) || value.now_ms > MAX_TIME - value.uncertainty_ms
      || (previous !== undefined && value.now_ms < previous)) throw unavailable();
  return Object.freeze({ now: value.now_ms, lower: Math.max(0, value.now_ms - value.uncertainty_ms), upper: value.now_ms + value.uncertainty_ms });
}

function validateOptionsResponse(value, intent, saved, before, after) {
  if (!exact(value, ['request', 'request_hash', 'challenge_id', 'nonce', 'iat', 'exp']) || !exact(value.request,
    ['profile', 'request_id', 'created_at_ms', 'expires_at_ms', 'issuer', 'environment', 'flow', 'client_id', 'registration', 'resource', 'scope', 'permissions', 'grant_limit', 'grant_expires_at_ms', 'code'])) throw unavailable();
  const request = value.request;
  if (request.profile !== 'atum-oauth-request-v1' || !uuid4(request.request_id) || !integer(request.created_at_ms, 0, MAX_TIME)
      || request.created_at_ms < before.lower || request.created_at_ms > after.upper || !integer(request.expires_at_ms, 0, MAX_TIME)
      || request.expires_at_ms !== Math.floor(Math.min(request.created_at_ms + 300_000, intent.detail.grant_expires_at_ms) / 1000) * 1000
      || request.grant_expires_at_ms > request.created_at_ms + saved.client.max_grant_lifetime_ms
      || request.expires_at_ms <= after.upper || request.issuer !== saved.registration.issuer || request.environment !== 'sandbox'
      || request.flow !== intent.optionsBody.flow || request.client_id !== saved.client.client_id || !same(request.registration, saved.registration)
      || request.resource !== saved.registration.audience || request.scope !== 'atum:invoke' || !same(request.permissions, intent.detail.permissions)
      || request.grant_limit !== intent.detail.grant_limit || request.grant_expires_at_ms !== intent.detail.grant_expires_at_ms
      || !same(request.code, intent.code) || Buffer.byteLength(canonical(request), 'utf8') > 8192) throw unavailable();
  const requestHash = digest('atum.oauth.request.v1\n', request);
  if (value.request_hash !== requestHash || !SHA256.test(value.request_hash) || !uuid4(value.challenge_id) || !base64(value.nonce, 32)
      || value.iat !== Math.floor(request.created_at_ms / 1000) || value.exp !== request.expires_at_ms / 1000) throw unavailable();
  return Object.freeze({ request, request_hash: requestHash, challenge_id: value.challenge_id, nonce: value.nonce, iat: value.iat, exp: value.exp });
}

function verifyResult(value, prepared, saved) {
  if (!exact(value, ['atum_request', 'request_id', 'request_hash', 'agent_key_thumbprint', 'state', 'expires_at_ms'])
      || !base64(value.atum_request, 32) || value.request_id !== prepared.request.request_id || value.request_hash !== prepared.request_hash
      || value.agent_key_thumbprint !== saved.key.thumbprint || value.expires_at_ms !== prepared.request.expires_at_ms) throw unavailable();
  if (value.state === 'expired') throw new AgentError('expired_token');
  if (value.state !== 'verified') throw unavailable();
  return snapshotData({ request: prepared.request, request_hash: prepared.request_hash, atum_request: value.atum_request, expires_at_ms: value.expires_at_ms });
}

function remaining(deadline, maximum) {
  const value = Math.floor(deadline - performance.now());
  if (value < 1) throw unavailable();
  return Math.min(value, maximum);
}

function proof(prepared, saved, deadline) {
  const header = { alg: 'ES256', typ: 'atum-oauth-request+jwt', jwk: saved.key.publicJwk };
  const claims = { iss: saved.client.client_id, aud: saved.registration.issuer, iat: prepared.iat, exp: prepared.exp,
    jti: prepared.challenge_id, request_id: prepared.request.request_id, request_hash: prepared.request_hash,
    nonce: prepared.nonce, purpose: 'prepare_owner_consent' };
  const encodedHeader = Buffer.from(canonical(header), 'utf8').toString('base64url');
  const encodedClaims = Buffer.from(canonical(claims), 'utf8').toString('base64url');
  const signingInput = Buffer.from(`${encodedHeader}.${encodedClaims}`, 'ascii');
  return saved.key.sign(signingInput, { timeoutMs: remaining(deadline, agentKeyTimeout(saved.key)) })
    .then(signature => `${encodedHeader}.${encodedClaims}.${Buffer.from(signature).toString('base64url')}`);
}

export function createRequestProofClient(config) {
  const saved = configCopy(config);
  const transport = createRequestTransport({ endpoints: { options_url: saved.endpoints.options_url, verify_url: saved.endpoints.verify_url },
    tls: saved.tls, timeoutMs: saved.timeoutMs, maxConcurrent: saved.maxConcurrent });
  let previousNow;
  let closed = false;
  let active = 0;
  const operations = new Set();

  function readClock() { const sample = clockSample(saved, previousNow); previousNow = sample.now; return sample; }
  function prepare(input) {
    if (closed || active >= saved.maxConcurrent) return Promise.reject(unavailable());
    active += 1;
    const deadline = performance.now() + saved.timeoutMs;
    let before; let intent;
    try { before = readClock(); intent = intentCopy(input, saved, before); }
    catch (error) { active -= 1; return Promise.reject(error instanceof AgentError ? error : invalidRequest()); }
    let delay;
    try { delay = remaining(deadline, saved.timeoutMs); }
    catch (error) { active -= 1; return Promise.reject(error); }
    return new Promise((resolve, reject) => {
      let settled = false;
      let live = true;
      let resolveCompletion;
      const operation = { completion: new Promise(done => { resolveCompletion = done; }), finish: undefined };
      const finish = (error, result) => {
        if (settled) return; settled = true; live = false; clearTimeout(timer);
        operations.delete(operation); active -= 1; resolveCompletion();
        if (error) reject(error instanceof AgentError ? error : unavailable()); else resolve(result);
      };
      operation.finish = finish;
      operations.add(operation);
      const timer = setTimeout(() => finish(unavailable()), delay);
      (async () => {
        try {
          const options = await transport.postJson('options', Buffer.from(canonical(intent.optionsBody), 'utf8'), deadline);
          if (!live || closed || performance.now() >= deadline) throw unavailable();
          const afterOptions = readClock();
          if (options.status !== 200) throw unavailable();
          const prepared = validateOptionsResponse(options.body, intent, saved, before, afterOptions);
          if (afterOptions.upper >= prepared.request.expires_at_ms) throw unavailable();
          const compact = await proof(prepared, saved, deadline);
          if (!live || closed || performance.now() >= deadline) throw unavailable();
          const afterSign = readClock();
          if (afterSign.upper >= prepared.request.expires_at_ms) throw unavailable();
          const verified = await transport.postJson('verify', Buffer.from(canonical({ challenge_id: prepared.challenge_id, proof: compact }), 'utf8'), deadline);
          if (!live || closed || performance.now() >= deadline) throw unavailable();
          const afterVerify = readClock();
          if (afterVerify.upper >= prepared.request.expires_at_ms || verified.status !== 200) throw unavailable();
          finish(null, verifyResult(verified.body, prepared, saved));
        } catch (error) { finish(error); }
      })();
    });
  }

  async function close() {
    if (!closed) {
      closed = true;
      const pending = [...operations];
      for (const operation of pending) operation.finish(unavailable());
      await transport.close();
      await Promise.all(pending.map(operation => operation.completion));
      return;
    }
    await transport.close();
  }

  return Object.freeze({ prepare, close });
}
