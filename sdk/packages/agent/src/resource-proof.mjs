import { createHash, randomBytes } from 'node:crypto';

import { canonicalAction, canonicalContext, intentHash, validateBoundIntent } from '@atum/verification/context';
import { validateResourceRegistration } from '@atum/verification/resource-profiles';

import { AgentError, agentKeyTimeout, assertAgentKey } from './key.mjs';
import { canonical, snapshotData } from './strict.mjs';

const MAX_TIME = 8_640_000_000_000_000;
const MAX_TOKEN_BYTES = 16 * 1024;
const CONFIG_FIELDS = new Set(['key', 'registration', 'descriptor', 'endpoint', 'clock', 'timeoutMs']);
const REGISTRATION_FIELDS = new Set(['issuer', 'audience', 'environment', 'tenant_id', 'resource_id', 'quota_scope_id',
  'operation_namespace', 'resource_profile_version', 'resource_profile_hash', 'policy_version', 'account_required_actions']);
const ENDPOINT_FIELDS = new Set(['method', 'url']);
const SIGN_FIELDS = new Set(['access_token', 'context', 'action_request', 'nonce']);
const CHALLENGE_FIELDS = new Set(['access_token', 'context', 'action_request']);
const COMPACT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?![\s\S])/;
const BASE64URL_32 = /^[A-Za-z0-9_-]{43}(?![\s\S])/;
const PARTY = /^[A-Za-z0-9:/._-]{1,256}(?![\s\S])/;
const ID = /^[A-Za-z0-9._:-]{1,128}(?![\s\S])/;
const HASH = /^sha256:[0-9a-f]{64}(?![\s\S])/;
const ACTIONS = new Set(['prices.read', 'order.preview', 'sandbox.execute', 'energy.purchase']);

function unavailable() { return new AgentError('temporarily_unavailable'); }
function invalidRequest() { throw new AgentError('invalid_request'); }
function invalidConfig() { throw new TypeError('invalid config'); }

function record(value, fields, invalid) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid();
  let prototype; let keys; let descriptors;
  try {
    prototype = Object.getPrototypeOf(value);
    keys = Reflect.ownKeys(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch { invalid(); }
  if (prototype !== Object.prototype || keys.some(key => typeof key !== 'string' || !fields.has(key))
      || keys.length !== Object.keys(descriptors).length) invalid();
  const copy = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) invalid();
    copy[key] = descriptor.value;
  }
  return copy;
}

function integer(value, lower, upper) {
  return typeof value === 'number' && Number.isSafeInteger(value) && !Object.is(value, -0)
    && value >= lower && value <= upper;
}

function configuredEndpoint(value) {
  const source = record(value, ENDPOINT_FIELDS, invalidConfig);
  if (Reflect.ownKeys(source).length !== ENDPOINT_FIELDS.size || source.method !== 'POST'
      || typeof source.url !== 'string' || !source.url.length || /\s|\\/.test(source.url)) invalidConfig();
  let parsed;
  try { parsed = new URL(source.url); } catch { invalidConfig(); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash
      || !parsed.hostname || !parsed.pathname || parsed.href !== source.url || /%/i.test(source.url)) invalidConfig();
  return Object.freeze({ method: source.method, url: source.url });
}

function configuredRegistration(value, descriptor) {
  let copy;
  try { copy = snapshotData(value); } catch { invalidConfig(); }
  const source = record(copy, REGISTRATION_FIELDS, invalidConfig);
  if (Reflect.ownKeys(source).length !== REGISTRATION_FIELDS.size) invalidConfig();
  try { return validateResourceRegistration(copy, descriptor).registration; } catch { invalidConfig(); }
}

function configuration(value) {
  const source = record(value, CONFIG_FIELDS, invalidConfig);
  if (!['key', 'registration', 'endpoint', 'clock'].every(field => Object.hasOwn(source, field))
      || Reflect.ownKeys(source).length < 4 || Reflect.ownKeys(source).length > 6
      || typeof source.clock !== 'function') invalidConfig();
  let key;
  try { key = assertAgentKey(source.key); } catch { invalidConfig(); }
  const timeoutMs = Object.hasOwn(source, 'timeoutMs') ? source.timeoutMs : 5000;
  if (!integer(timeoutMs, 1, 5000)) invalidConfig();
  let descriptor;
  try { descriptor = Object.hasOwn(source, 'descriptor') ? snapshotData(source.descriptor) : undefined; } catch { invalidConfig(); }
  return Object.freeze({ key, registration: configuredRegistration(source.registration, descriptor), descriptor,
    endpoint: configuredEndpoint(source.endpoint), clock: source.clock, timeoutMs });
}

function canonicalNonce(value) {
  if (typeof value !== 'string' || !BASE64URL_32.test(value)) return false;
  let bytes;
  try { bytes = Buffer.from(value, 'base64url'); } catch { return false; }
  return bytes.byteLength === 32 && bytes.toString('base64url') === value;
}

function accessToken(value) {
  if (typeof value !== 'string' || value.length < 5 || value.length > MAX_TOKEN_BYTES
      || Buffer.byteLength(value, 'ascii') !== value.length || !COMPACT.test(value)) invalidRequest();
  return value;
}

function input(value, challenge, saved) {
  let copy;
  try { copy = snapshotData(value); } catch { invalidRequest(); }
  const fields = challenge ? CHALLENGE_FIELDS : SIGN_FIELDS;
  const source = record(copy, fields, invalidRequest);
  if (Reflect.ownKeys(source).length !== fields.size || (!challenge && !canonicalNonce(source.nonce))) invalidRequest();
  const token = accessToken(source.access_token);
  try {
    validateBoundIntent(source.context, source.action_request, saved.registration, saved.descriptor);
    if (source.context.agent_key_thumbprint !== saved.key.thumbprint) invalidRequest();
  } catch (error) {
    if (error instanceof AgentError) throw error;
    invalidRequest();
  }
  const context = canonicalContext(source.context, saved.descriptor);
  const action = canonicalAction(source.action_request, saved.descriptor);
  return Object.freeze({ token, context: source.context, action_request: source.action_request,
    body: `{"context":${context},"action_request":${action}}`, nonce: challenge ? null : source.nonce });
}

function clockSample(saved, previousNow) {
  let value;
  try { value = snapshotData(saved.clock()); } catch { throw unavailable(); }
  const keys = value !== null && typeof value === 'object' && !Array.isArray(value) ? Object.keys(value) : [];
  if (keys.length !== 3 || !['now_ms', 'uncertainty_ms', 'healthy'].every(field => Object.hasOwn(value, field))
      || value.healthy !== true || !integer(value.now_ms, 0, MAX_TIME)
      || !integer(value.uncertainty_ms, 0, 1000) || value.now_ms > MAX_TIME - value.uncertainty_ms
      || (previousNow !== undefined && value.now_ms < previousNow)) throw unavailable();
  return Object.freeze({ now: value.now_ms, upper: value.now_ms + value.uncertainty_ms });
}

function remaining(deadline, maximum) {
  const available = Math.floor(deadline - performance.now());
  if (available < 1) throw unavailable();
  return Math.min(available, maximum);
}

function compactPart(value) {
  return Buffer.from(canonical(value), 'utf8').toString('base64url');
}

export function createProtectedRequestSigner(config) {
  const saved = configuration(config);

  function run(value, challenge) {
    const deadline = performance.now() + saved.timeoutMs;
    let captured;
    try { captured = input(value, challenge, saved); } catch (error) {
      return Promise.reject(error instanceof AgentError ? error : new AgentError('invalid_request'));
    }
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (error, result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(error instanceof AgentError ? error : unavailable()); else resolve(result);
      };
      const timer = setTimeout(() => finish(unavailable()), Math.max(0, Math.ceil(deadline - performance.now())));
      (async () => {
        try {
          let previousNow;
          let maximumUpper = -1;
          const readClock = () => {
            const measured = clockSample(saved, previousNow);
            previousNow = measured.now;
            maximumUpper = Math.max(maximumUpper, measured.upper);
            return measured;
          };
          const measured = readClock();
          const iat = Math.floor(measured.now / 1000);
          const header = { alg: 'ES256', jwk: saved.key.publicJwk, typ: 'dpop+jwt' };
          const claims = { ath: createHash('sha256').update(captured.token, 'ascii').digest('base64url'),
            atum_intent_hash: intentHash(captured.context, saved.descriptor), htm: saved.endpoint.method, htu: saved.endpoint.url,
            iat, jti: randomBytes(16).toString('base64url') };
          if (!challenge) claims.nonce = captured.nonce;
          const protectedHeader = compactPart(header);
          const payload = compactPart(claims);
          const signingInput = Buffer.from(`${protectedHeader}.${payload}`, 'ascii');
          const signature = await saved.key.sign(signingInput,
            { timeoutMs: remaining(deadline, agentKeyTimeout(saved.key)) });
          if (settled || performance.now() >= deadline) throw unavailable();
          readClock();
          if (maximumUpper - iat * 1000 > 60_000) throw unavailable();
          if (performance.now() >= deadline) throw unavailable();
          const result = Object.freeze({ authorization: `DPoP ${captured.token}`,
            dpop: `${protectedHeader}.${payload}.${Buffer.from(signature).toString('base64url')}`,
            body: captured.body, method: saved.endpoint.method, url: saved.endpoint.url });
          finish(null, result);
        } catch (error) { finish(error); }
      })();
    });
  }

  return Object.freeze({
    sign: value => run(value, false),
    signChallenge: value => run(value, true),
  });
}
