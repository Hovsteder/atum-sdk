import { createHash } from 'node:crypto';
import { calculateJwkThumbprint, importJWK, jwtVerify } from 'jose';

import { intentHash, parseStrictJson, validateBoundIntent } from './context.mjs';
import { VerificationError } from './errors.mjs';

const B64_INVALID = /[^A-Za-z0-9_-]/;
const ID_INVALID = /[^A-Za-z0-9._:-]/;
const TOKEN_FIELDS = new Set(['iss', 'aud', 'sub', 'client_id', 'jti', 'iat', 'exp', 'nbf', 'cnf', 'scope', 'atum']);
const ATUM_FIELDS = new Set(['proof_profile', 'environment', 'tenant_id', 'resource_id', 'quota_scope_id', 'operation_namespace', 'resource_profile_version', 'resource_profile_hash', 'policy_version', 'grant_id', 'grant_version', 'consent_hash', 'account_binding_id', 'account_binding_version']);
const CONTEXT_ATUM_FIELDS = [...ATUM_FIELDS].filter(field => field !== 'proof_profile');
const REGISTRATION_FIELDS = new Set(['issuer', 'audience', 'environment', 'tenant_id', 'resource_id', 'quota_scope_id', 'operation_namespace', 'resource_profile_version', 'resource_profile_hash', 'policy_version', 'account_required_actions']);

const invalid = () => { throw new VerificationError('invalid_proof'); };
const invalidRequest = () => { throw new VerificationError('invalid_request'); };
const unavailable = () => { throw new VerificationError('temporarily_unavailable'); };
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, fields) => plain(value) && Object.keys(value).length === fields.size && Object.keys(value).every(key => fields.has(key));
const integer = value => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
const chars = (value, expression, min, max) => typeof value === 'string' && value.length >= min && value.length <= max && !expression.test(value);
const sha256 = value => typeof value === 'string' && value.length === 71 && value.startsWith('sha256:') && !/[^0-9a-f]/.test(value.slice(7));

function freezeCopy(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(freezeCopy));
  if (plain(value)) return Object.freeze(Object.fromEntries(Object.entries(value).map(([key, item]) => [key, freezeCopy(item)])));
  return value;
}
function canonicalB64(value, bytes) {
  if (!chars(value, B64_INVALID, 1, Number.MAX_SAFE_INTEGER)) invalid();
  let decoded;
  try { decoded = Buffer.from(value, 'base64url'); } catch { invalid(); }
  if (decoded.length !== bytes || decoded.toString('base64url') !== value) invalid();
  return decoded;
}
function canonicalB64Config(value) {
  if (!chars(value, B64_INVALID, 1, Number.MAX_SAFE_INTEGER)) throw new TypeError('invalid config');
  const decoded = Buffer.from(value, 'base64url');
  if (!decoded.length || decoded.toString('base64url') !== value) throw new TypeError('invalid config');
  return decoded;
}
function compact(token, max, limits) {
  if (typeof token !== 'string' || token.length > max || /[\x00-\x20\x7f]/.test(token)) invalid();
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some(part => !chars(part, B64_INVALID, 1, Number.MAX_SAFE_INTEGER))) invalid();
  let headerBytes; let payloadBytes;
  try { headerBytes = Buffer.from(parts[0], 'base64url'); payloadBytes = Buffer.from(parts[1], 'base64url'); } catch { invalid(); }
  if (headerBytes.toString('base64url') !== parts[0] || payloadBytes.toString('base64url') !== parts[1]
      || Buffer.from(parts[2], 'base64url').toString('base64url') !== parts[2] || headerBytes.length > limits.header || payloadBytes.length > limits.payload) invalid();
  try { return { header: parseStrictJson(headerBytes, limits.header), payload: parseStrictJson(payloadBytes, limits.payload) }; } catch { invalid(); }
}
function endpointConfig(endpoint) {
  if (!exact(endpoint, new Set(['method', 'url'])) || endpoint.method !== 'POST' || typeof endpoint.url !== 'string') throw new TypeError('invalid config');
  let parsed;
  try { parsed = new URL(endpoint.url); } catch { throw new TypeError('invalid config'); }
  if (parsed.protocol !== 'https:' || parsed.search || parsed.hash || parsed.username || parsed.password || /%/i.test(endpoint.url) || parsed.href !== endpoint.url) throw new TypeError('invalid config');
  return freezeCopy({ method: endpoint.method, url: endpoint.url });
}
function issuerKey(jwk) {
  const fields = new Set(['kty', 'n', 'e', 'kid', 'alg', 'use']);
  if (!exact(jwk, fields) || jwk.kty !== 'RSA' || jwk.e !== 'AQAB' || jwk.alg !== 'RS256' || jwk.use !== 'sig' || typeof jwk.kid !== 'string' || !jwk.kid || jwk.kid.length > 256 || /[\x00-\x20\x7f]/.test(jwk.kid)) throw new TypeError('invalid config');
  const modulus = canonicalB64Config(jwk.n);
  const bits = modulus.length * 8 - Math.clz32(modulus[0]) + 24;
  if (modulus[0] === 0 || bits < 2048 || bits > 4096) throw new TypeError('invalid config');
  return freezeCopy(jwk);
}
function readClock(clock) {
  let value;
  try { value = clock(); } catch { unavailable(); }
  if (!exact(value, new Set(['now_ms', 'uncertainty_ms', 'healthy'])) || !integer(value.now_ms) || !integer(value.uncertainty_ms) || value.uncertainty_ms > 1000 || value.healthy !== true || value.now_ms > Number.MAX_SAFE_INTEGER - value.uncertainty_ms || value.now_ms + value.uncertainty_ms > 8640000000000000) unavailable();
  return { now: value.now_ms, upper: value.now_ms + value.uncertainty_ms };
}
function registrationConfig(value) {
  if (!exact(value, REGISTRATION_FIELDS) || !chars(value.issuer, /[^A-Za-z0-9:/._-]/, 1, 256) || !chars(value.audience, /[^A-Za-z0-9:/._-]/, 1, 256)
      || value.environment !== 'sandbox' || value.resource_profile_version !== 'v1-draft.1' || !sha256(value.resource_profile_hash)
      || ['tenant_id', 'resource_id', 'quota_scope_id', 'operation_namespace', 'policy_version'].some(key => !chars(value[key], ID_INVALID, 1, 128))
      || !Array.isArray(value.account_required_actions) || value.account_required_actions.some(action => !['prices.read', 'order.preview', 'sandbox.execute'].includes(action)) || new Set(value.account_required_actions).size !== value.account_required_actions.length) throw new TypeError('invalid config');
  return freezeCopy(structuredClone(value));
}
function tokenTimes(claims, clock) {
  return integer(claims.iat) && integer(claims.exp) && (!Object.hasOwn(claims, 'nbf') || integer(claims.nbf))
    && claims.exp > claims.iat && claims.exp - claims.iat <= 300 && claims.exp <= Number.MAX_SAFE_INTEGER / 1000
    && claims.iat <= Number.MAX_SAFE_INTEGER / 1000 && (!Object.hasOwn(claims, 'nbf') || claims.nbf <= Number.MAX_SAFE_INTEGER / 1000)
    && claims.exp * 1000 > clock.upper && claims.iat * 1000 <= clock.upper
    && (claims.nbf === undefined || claims.nbf * 1000 <= clock.now - (clock.upper - clock.now));
}
function proofTimes(proof, clock) {
  return integer(proof.iat) && proof.iat <= Number.MAX_SAFE_INTEGER / 1000 && proof.iat * 1000 <= clock.upper && clock.upper - proof.iat * 1000 <= 60000;
}
function inputShape(input, endpoint) {
  if (!exact(input, new Set(['authorization', 'dpop', 'body', 'method', 'url'])) || input.method !== endpoint.method || input.url !== endpoint.url || typeof input.authorization !== 'string' || typeof input.dpop !== 'string' || (typeof input.body !== 'string' && !(input.body instanceof Uint8Array))) invalidRequest();
  if (input.authorization.length > 16416 || input.dpop.length > 8192 || (typeof input.body === 'string' ? input.body.length > 32768 : input.body.byteLength > 32768)) invalidRequest();
  if (/[\r\n\x00]/.test(input.authorization) || input.authorization.includes(',')) invalidRequest();
  const auth = /^DPoP +([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i.exec(input.authorization);
  if (!auth || input.dpop.includes(',') || /[\r\n\x00]/.test(input.dpop)) invalidRequest();
  return Object.freeze({ token: auth[1], dpop: String(input.dpop), body: input.body instanceof Uint8Array ? new Uint8Array(input.body) : String(input.body) });
}
function same(value, context, fields) { return fields.every(field => value[field] === context[field]); }
function checkDeadline(deadlineAt) {
  if (deadlineAt === undefined) return;
  if (typeof deadlineAt !== 'number' || !Number.isFinite(deadlineAt) || deadlineAt <= performance.now() || deadlineAt > performance.now() + 5000) unavailable();
}

export async function createProofValidator(config) {
  if (!exact(config, new Set(['registration', 'issuerKeys', 'endpoint', 'clock'])) || typeof config.clock !== 'function' || !Array.isArray(config.issuerKeys) || !config.issuerKeys.length) throw new TypeError('invalid config');
  const endpoint = endpointConfig(config.endpoint);
  let registration;
  try { registration = registrationConfig(config.registration); } catch (error) { if (error instanceof TypeError) throw error; throw new TypeError('invalid config'); }
  const clock = config.clock;
  const issuerKeys = config.issuerKeys.map(issuerKey);
  if (new Set(issuerKeys.map(key => key.kid)).size !== issuerKeys.length) throw new TypeError('invalid config');
  const imported = new Map();
  try { for (const key of issuerKeys) imported.set(key.kid, await importJWK(key, 'RS256')); } catch { throw new TypeError('invalid config'); }
  return Object.freeze({ async validate(input, fields, deadlineAt, observeEachCrypto = false) {
    try {
      checkDeadline(deadlineAt);
      const request = inputShape(input, endpoint);
      const initialClock = readClock(clock);
      let previousClock = initialClock;
      let maximumUpper = initialClock.upper;
      const afterCrypto = () => {
        checkDeadline(deadlineAt);
        if (!observeEachCrypto) return { now: previousClock.now, upper: maximumUpper };
        const observed = readClock(clock);
        if (observed.now < previousClock.now) unavailable();
        previousClock = observed;
        maximumUpper = Math.max(maximumUpper, observed.upper);
        return { now: observed.now, upper: maximumUpper };
      };
      const tokenDecoded = compact(request.token, 16384, { header: 4096, payload: 16384 });
      if (!exact(tokenDecoded.header, new Set(['typ', 'alg', 'kid'])) || tokenDecoded.header.typ !== 'at+jwt' || tokenDecoded.header.alg !== 'RS256' || typeof tokenDecoded.header.kid !== 'string') invalid();
      const key = imported.get(tokenDecoded.header.kid); if (!key) invalid();
      const tokenFields = new Set([...TOKEN_FIELDS].filter(field => field !== 'nbf'));
      if (Object.hasOwn(tokenDecoded.payload, 'nbf')) tokenFields.add('nbf');
      if (!exact(tokenDecoded.payload, tokenFields) || typeof tokenDecoded.payload.iss !== 'string' || typeof tokenDecoded.payload.aud !== 'string') invalid();
      const verifiedToken = await jwtVerify(request.token, key, { algorithms: ['RS256'], issuer: registration.issuer, audience: registration.audience, typ: 'at+jwt', currentDate: new Date(initialClock.upper), clockTolerance: 0, requiredClaims: ['iss', 'aud', 'sub', 'client_id', 'jti', 'iat', 'exp'] });
      const tokenClock = afterCrypto();
      const claims = verifiedToken.payload;
      if (!tokenTimes(claims, tokenClock) || claims.iss !== registration.issuer || claims.aud !== registration.audience || typeof claims.sub !== 'string' || !chars(claims.client_id, ID_INVALID, 1, 128) || !chars(claims.jti, ID_INVALID, 1, 128) || claims.scope !== 'atum:invoke') invalid();
      let body;
      try { body = parseStrictJson(request.body, 32768); if (!exact(body, new Set(['context', 'action_request']))) invalidRequest(); validateBoundIntent(body.context, body.action_request, registration); } catch (error) { if (error instanceof VerificationError) throw error; invalidRequest(); }
      const context = freezeCopy(structuredClone(body.context));
      if (claims.sub !== context.scoped_subject || !exact(claims.cnf, new Set(['jkt'])) || claims.cnf.jkt !== context.agent_key_thumbprint || !exact(claims.atum, ATUM_FIELDS) || claims.atum.proof_profile !== 'atum-dpop-v1-draft.1' || !same(claims.atum, context, CONTEXT_ATUM_FIELDS)) invalid();
      const proofDecoded = compact(request.dpop, 8192, { header: 4096, payload: 8192 });
      if (!exact(proofDecoded.header, new Set(['typ', 'alg', 'jwk'])) || proofDecoded.header.typ !== 'dpop+jwt' || proofDecoded.header.alg !== 'ES256' || !exact(proofDecoded.header.jwk, new Set(['kty', 'crv', 'x', 'y'])) || proofDecoded.header.jwk.kty !== 'EC' || proofDecoded.header.jwk.crv !== 'P-256') invalid();
      canonicalB64(proofDecoded.header.jwk.x, 32); canonicalB64(proofDecoded.header.jwk.y, 32);
      const agentKey = await importJWK(proofDecoded.header.jwk, 'ES256');
      if (!tokenTimes(claims, afterCrypto())) invalid();
      const thumbprint = await calculateJwkThumbprint(proofDecoded.header.jwk, 'sha256');
      if (!tokenTimes(claims, afterCrypto())) invalid();
      if (thumbprint !== context.agent_key_thumbprint) invalid();
      if (!exact(proofDecoded.payload, fields)) invalid();
      const proof = (await jwtVerify(request.dpop, agentKey, { algorithms: ['ES256'], typ: 'dpop+jwt', currentDate: new Date(initialClock.upper), clockTolerance: 0 })).payload;
      const proofClock = afterCrypto();
      if (!tokenTimes(claims, proofClock) || !proofTimes(proof, proofClock) || !chars(proof.jti, B64_INVALID, 16, 128) || proof.htm !== endpoint.method || proof.htu !== endpoint.url || proof.ath !== createHash('sha256').update(request.token, 'ascii').digest('base64url') || proof.atum_intent_hash !== intentHash(context)) invalid();
      if (fields.has('nonce')) canonicalB64(proof.nonce, 32);
      const finalClock = readClock(clock);
      if (finalClock.now < previousClock.now) unavailable();
      maximumUpper = Math.max(maximumUpper, finalClock.upper);
      const finalFreshness = observeEachCrypto ? { now: finalClock.now, upper: maximumUpper } : finalClock;
      if (!tokenTimes(claims, finalFreshness) || !proofTimes(proof, finalFreshness)) invalid();
      return Object.freeze({ context, endpoint_url: endpoint.url, intent_hash: intentHash(context), agent_key_thumbprint: context.agent_key_thumbprint,
        proof_jti: proof.jti, proof_iat_ms: proof.iat * 1000, replay_expires_at_ms: proof.iat * 1000 + 61000,
        token_expires_at_ms: claims.exp * 1000, client_id: claims.client_id, nonce: proof.nonce, initialClock, finalClock, maximumUpper, claims, proof });
    } catch (error) {
      if (error instanceof VerificationError) throw error;
      throw new VerificationError('invalid_proof');
    }
  }, recheckAfterStorage(verified) {
    const completedClock = readClock(clock);
    if (completedClock.now < verified.finalClock.now) unavailable();
    if (!tokenTimes(verified.claims, completedClock) || !proofTimes(verified.proof, completedClock)) invalid();
    return completedClock;
  } });
}
