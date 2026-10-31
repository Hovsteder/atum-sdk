import { randomBytes, X509Certificate } from 'node:crypto';
import https from 'node:https';
import { isIP } from 'node:net';
import tls from 'node:tls';
import { MERX_ENERGY_V1, MERX_SANDBOX_V1, normalizeProfileGrant, validateResourceRegistration } from '@atum/verification/resource-profiles';

import { AgentError, agentKeyTimeout, assertAgentKey } from './key.mjs';
import { canonical, parseClosedJson, snapshotData } from './strict.mjs';

const MAX_TIME = 8_640_000_000_000_000;
const MAX_REQUEST_BYTES = 16 * 1024;
const MAX_RESPONSE_BYTES = 32 * 1024;
const MAX_HEADERS = 64;
const MAX_HEADER_BYTES = 16 * 1024;
const MAX_CA_BYTES = 64 * 1024;
const MAX_CA_CERTIFICATES = 8;
const PEM_BEGIN = '-----BEGIN CERTIFICATE-----';
const PEM_END = '-----END CERTIFICATE-----';
const PEM_CERTIFICATE = /^-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/]{1,64}={0,2}\r?\n)+-----END CERTIFICATE-----$/;
const ID = /^[A-Za-z0-9._:-]{1,128}$/;
const OPAQUE_ARTIFACT = /^[A-Za-z0-9_-]{43}$/;
const COMPACT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const ACTIONS = new Set(['prices.read', 'order.preview', 'sandbox.execute', 'energy.purchase']);
const CONFIG_FIELDS = new Set(['client_id', 'token_url', 'tls', 'key', 'clock', 'registration', 'descriptor', 'timeoutMs', 'maxConcurrent']);
const CODE_FIELDS = new Set(['code', 'code_verifier', 'redirect_uri', 'expected_authorization_details']);
const DEVICE_FIELDS = new Set(['device_code', 'expected_authorization_details']);
const REFRESH_FIELDS = new Set(['refresh_token', 'expected_authorization_details']);
const SUCCESS_FIELDS = ['access_token', 'expires_in', 'refresh_token', 'scope', 'token_type', 'authorization_details'];
const ERROR_FIELDS = new Set(['error', 'error_description']);

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
  const result = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) invalid();
    result[key] = descriptor.value;
  }
  return result;
}

function exact(value, fields) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).length === fields.length
    && fields.every(field => Object.hasOwn(value, field));
}

function integer(value, lower, upper) {
  return typeof value === 'number' && Number.isSafeInteger(value) && !Object.is(value, -0)
    && value >= lower && value <= upper;
}

function canonicalBase64(value, bytes) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
  let decoded;
  try { decoded = Buffer.from(value, 'base64url'); } catch { return false; }
  return decoded.byteLength === bytes && decoded.toString('base64url') === value;
}

function caBundle(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') < 1
      || Buffer.byteLength(value, 'utf8') > MAX_CA_BYTES) invalidConfig();
  let offset = 0;
  let count = 0;
  while (offset < value.length) {
    const whitespace = value.slice(offset).match(/^[ \t\r\n]*/)?.[0] ?? '';
    offset += whitespace.length;
    if (offset === value.length) break;
    if (!value.startsWith(PEM_BEGIN, offset)) invalidConfig();
    const end = value.indexOf(PEM_END, offset + PEM_BEGIN.length);
    if (end === -1) invalidConfig();
    const block = value.slice(offset, end + PEM_END.length);
    if (!PEM_CERTIFICATE.test(block) || ++count > MAX_CA_CERTIFICATES) invalidConfig();
    try { if (!new X509Certificate(block).ca) invalidConfig(); } catch { invalidConfig(); }
    offset = end + PEM_END.length;
  }
  if (count === 0) invalidConfig();
  return value;
}

function endpoint(value) {
  if (typeof value !== 'string' || !value.length || /\s|\\/.test(value)) invalidConfig();
  let parsed;
  try { parsed = new URL(value); } catch { invalidConfig(); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash
      || !parsed.hostname || !parsed.pathname || parsed.href !== value) invalidConfig();
  return Object.freeze({ href: parsed.href, hostname: parsed.hostname, port: parsed.port,
    host: parsed.host, path: parsed.pathname });
}

function configuration(value) {
  const source = record(value, CONFIG_FIELDS, invalidConfig);
  if (!['client_id', 'token_url', 'tls', 'key', 'clock'].every(field => Object.hasOwn(source, field))
      || Reflect.ownKeys(source).length < 5 || Reflect.ownKeys(source).length > 9
      || typeof source.client_id !== 'string' || !ID.test(source.client_id) || typeof source.clock !== 'function') invalidConfig();
  const tlsFields = source.tls && Object.hasOwn(source.tls, 'ca') ? new Set(['ca']) : new Set();
  const transportTls = record(source.tls, tlsFields, invalidConfig);
  const ca = Object.hasOwn(transportTls, 'ca') ? caBundle(transportTls.ca) : undefined;
  const timeoutMs = Object.hasOwn(source, 'timeoutMs') ? source.timeoutMs : 5000;
  const maxConcurrent = Object.hasOwn(source, 'maxConcurrent') ? source.maxConcurrent : 4;
  if (!integer(timeoutMs, 1, 5000) || !integer(maxConcurrent, 1, 16)) invalidConfig();
  let key;
  try { key = assertAgentKey(source.key); } catch { invalidConfig(); }
  let profile = null;
  if (Object.hasOwn(source, 'registration') || Object.hasOwn(source, 'descriptor')) {
    if (!Object.hasOwn(source, 'registration')) invalidConfig();
    try { profile = validateResourceRegistration(snapshotData(source.registration),
      Object.hasOwn(source, 'descriptor') ? snapshotData(source.descriptor) : undefined).profile; } catch { invalidConfig(); }
  }
  const target = endpoint(source.token_url);
  try { tls.createSecureContext({ ca, minVersion: 'TLSv1.2' }); } catch { invalidConfig(); }
  return Object.freeze({ client_id: source.client_id, target, ca, key, profile, clock: source.clock, timeoutMs, maxConcurrent });
}

function responseHeaders(response) {
  const raw = response.rawHeaders;
  if (!Array.isArray(raw) || raw.length % 2 || raw.length / 2 > MAX_HEADERS
      || Buffer.byteLength(raw.join(''), 'utf8') > MAX_HEADER_BYTES) return null;
  const values = new Map();
  for (let index = 0; index < raw.length; index += 2) {
    const name = raw[index];
    const entry = raw[index + 1];
    if (typeof name !== 'string' || typeof entry !== 'string') return null;
    const lowered = name.toLowerCase();
    if (values.has(lowered)) return null;
    values.set(lowered, entry);
  }
  const length = values.get('content-length');
  if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(values.get('content-type') ?? '')
      || values.has('transfer-encoding') || values.has('content-encoding') || values.has('set-cookie')
      || values.get('cache-control') !== 'no-store' || typeof length !== 'string'
      || !/^(0|[1-9][0-9]*)$/.test(length) || Number(length) > MAX_RESPONSE_BYTES) return null;
  return Object.freeze({ length: Number(length), nonce: values.get('dpop-nonce') });
}

function responseValue(response, chunks) {
  const headers = responseHeaders(response);
  if (headers === null || chunks.length !== headers.length || !Number.isSafeInteger(response.statusCode)
      || response.statusCode < 200 || response.statusCode > 599
      || (response.statusCode >= 300 && response.statusCode < 400)) throw unavailable();
  let body;
  try { body = snapshotData(parseClosedJson(chunks, MAX_RESPONSE_BYTES)); } catch { throw unavailable(); }
  const result = { status: response.statusCode, body };
  if (headers.nonce !== undefined) result.dpop_nonce = headers.nonce;
  return Object.freeze(result);
}

function createTokenTransport(saved) {
  let agent;
  try {
    agent = new https.Agent({ keepAlive: false, maxSockets: saved.maxConcurrent, maxFreeSockets: 0,
      maxCachedSessions: 0, ...(saved.ca === undefined ? {} : { ca: saved.ca }), minVersion: 'TLSv1.2', rejectUnauthorized: true });
  } catch { invalidConfig(); }
  let closed = false;
  const operations = new Set();

  function post(form, dpop, deadline) {
    if (closed) return Promise.reject(unavailable());
    if (typeof form !== 'string' || Buffer.byteLength(form, 'utf8') > MAX_REQUEST_BYTES
        || typeof dpop !== 'string' || dpop.length > 8192 || !COMPACT.test(dpop)
        || typeof deadline !== 'number' || !Number.isFinite(deadline) || deadline <= performance.now()) return Promise.reject(unavailable());
    const body = Buffer.from(form, 'utf8');
    return new Promise((resolve, reject) => {
      let terminal = false;
      let terminalError;
      let terminalValue;
      let released = false;
      let resolveCompletion;
      const operation = { request: null, completion: new Promise(done => { resolveCompletion = done; }) };
      operations.add(operation);
      const recordResult = (error, result) => {
        if (terminal) return;
        terminal = true;
        terminalError = error instanceof Error ? error : null;
        terminalValue = result;
      };
      const release = () => {
        if (released) return;
        released = true;
        clearTimeout(timer);
        operations.delete(operation);
        resolveCompletion();
      };
      const destroy = () => {
        if (!operation.request) return;
        try { operation.request.destroy(unavailable()); } catch { recordResult(unavailable()); }
      };
      const finish = () => {
        if (!terminal) recordResult(unavailable());
        if (terminalError) reject(terminalError); else resolve(terminalValue);
        release();
      };
      operation.destroy = () => { recordResult(unavailable()); destroy(); };
      const timer = setTimeout(() => { recordResult(unavailable()); destroy(); }, Math.max(0, deadline - performance.now()));
      try {
        const request = https.request({ protocol: 'https:', hostname: saved.target.hostname,
          port: saved.target.port || undefined, servername: isIP(saved.target.hostname) ? undefined : saved.target.hostname, path: saved.target.path,
          method: 'POST', agent, minVersion: 'TLSv1.2', rejectUnauthorized: true,
          headers: { Host: saved.target.host, 'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': String(body.length), Accept: 'application/json', DPoP: dpop,
            'Cache-Control': 'no-store', Connection: 'close' } }, response => {
          const header = responseHeaders(response);
          const chunks = [];
          let size = 0;
          let complete = false;
          const fail = () => { recordResult(unavailable()); destroy(); };
          if (header === null) { fail(); return; }
          response.on('data', chunk => {
            size += chunk.length;
            if (size > MAX_RESPONSE_BYTES) {
              fail();
              try { response.destroy(unavailable()); } catch { /* request close releases the operation */ }
            } else chunks.push(chunk);
          });
          response.once('error', fail);
          response.once('aborted', fail);
          response.once('end', () => {
            complete = true;
            try { recordResult(null, responseValue(response, Buffer.concat(chunks))); }
            catch (error) { recordResult(error); destroy(); }
          });
          response.once('close', () => { if (!complete) fail(); });
        });
        operation.request = request;
        request.once('error', () => recordResult(unavailable()));
        request.once('close', finish);
        request.end(body);
      } catch {
        recordResult(unavailable());
        if (operation.request) destroy(); else { release(); reject(unavailable()); }
      }
    });
  }

  return Object.freeze({
    post,
    async close() {
      if (!closed) {
        closed = true;
        for (const operation of [...operations]) operation.destroy();
        try { agent.destroy(); } catch { /* request close settles each operation */ }
      }
      await Promise.all([...operations].map(operation => operation.completion));
    },
  });
}

function permission(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || !ACTIONS.has(value.action)) throw invalidRequest();
  if (value.action === 'prices.read') {
    if (!exact(value, ['action'])) throw invalidRequest();
    return Object.freeze({ action: value.action });
  }
  if (!exact(value, ['action', 'max_amount', 'max_duration', 'max_price_sun'])
      || !integer(value.max_amount, 1, 1_000_000_000) || !integer(value.max_duration, 1, 2_592_000)
      || (value.max_price_sun !== null && !integer(value.max_price_sun, 1, 1_000_000_000_000))) throw invalidRequest();
  return Object.freeze({ action: value.action, max_amount: value.max_amount,
    max_duration: value.max_duration, max_price_sun: value.max_price_sun });
}

function authorizationDetails(value, configuredProfile = null) {
  let source;
  try { source = snapshotData(value); } catch { throw invalidRequest(); }
  if (!Array.isArray(source) || source.length !== 1 || !exact(source[0], ['type', 'permissions', 'grant_limit', 'grant_expires_at_ms'])
      || source[0].type !== 'atum' || !Array.isArray(source[0].permissions) || source[0].permissions.length < 1
      || source[0].permissions.length > (configuredProfile?.kind === 'service' ? configuredProfile.actions.length : 3)
      || !integer(source[0].grant_limit, 0, 1_000_000_000)
      || !integer(source[0].grant_expires_at_ms, 1, MAX_TIME)) throw invalidRequest();
  const profile = configuredProfile ?? (source[0].permissions.some(item => item?.action === 'energy.purchase') ? MERX_ENERGY_V1 : MERX_SANDBOX_V1);
  let grant;
  try { grant = normalizeProfileGrant({ permissions: source[0].permissions, grant_limit: source[0].grant_limit,
    grant_expires_at_ms: source[0].grant_expires_at_ms }, profile); } catch { throw invalidRequest(); }
  return Object.freeze([Object.freeze({ type: 'atum', permissions: grant.permissions,
    grant_limit: grant.grant_limit, grant_expires_at_ms: grant.grant_expires_at_ms })]);
}

function redirect(value) {
  if (typeof value !== 'string' || !value.length || /\s|\\/.test(value)) throw invalidRequest();
  let parsed;
  try { parsed = new URL(value); } catch { throw invalidRequest(); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash
      || !parsed.hostname || parsed.href !== value) throw invalidRequest();
  return value;
}

function operationInput(kind, value, profile) {
  const fields = kind === 'code' ? CODE_FIELDS : kind === 'device' ? DEVICE_FIELDS : REFRESH_FIELDS;
  const source = record(value, fields, invalidRequest);
  if (Reflect.ownKeys(source).length !== fields.size) throw invalidRequest();
  const expected = authorizationDetails(source.expected_authorization_details, profile);
  if (kind === 'code') {
    if (typeof source.code !== 'string' || !OPAQUE_ARTIFACT.test(source.code)
        || !canonicalBase64(source.code_verifier, 32)) throw invalidRequest();
    return Object.freeze({ expected, submittedRefresh: null,
      form: new URLSearchParams([['grant_type', 'authorization_code'], ['client_id', ''], ['code', source.code],
        ['redirect_uri', redirect(source.redirect_uri)], ['code_verifier', source.code_verifier]]) });
  }
  const artifact = kind === 'device' ? source.device_code : source.refresh_token;
  if (typeof artifact !== 'string' || !OPAQUE_ARTIFACT.test(artifact)) throw invalidRequest();
  return Object.freeze({ expected, submittedRefresh: kind === 'refresh' ? artifact : null,
    form: new URLSearchParams(kind === 'device'
      ? [['grant_type', 'urn:ietf:params:oauth:grant-type:device_code'], ['client_id', ''], ['device_code', artifact]]
      : [['grant_type', 'refresh_token'], ['client_id', ''], ['refresh_token', artifact]]) });
}

function clockSample(saved, previous) {
  let value;
  try { value = snapshotData(saved.clock()); } catch { throw unavailable(); }
  if (!exact(value, ['now_ms', 'uncertainty_ms', 'healthy']) || value.healthy !== true
      || !integer(value.now_ms, 0, MAX_TIME) || !integer(value.uncertainty_ms, 0, 1000)
      || value.now_ms > MAX_TIME - value.uncertainty_ms || (previous !== undefined && value.now_ms < previous)) throw unavailable();
  return Object.freeze({ now: value.now_ms, upper: value.now_ms + value.uncertainty_ms });
}

function remaining(deadline, maximum) {
  const value = Math.floor(deadline - performance.now());
  if (value < 1) throw unavailable();
  return Math.min(value, maximum);
}

async function dpop(saved, readClock, nonce, deadline) {
  const measured = readClock();
  const header = { alg: 'ES256', typ: 'dpop+jwt', jwk: saved.key.publicJwk };
  const claims = { htm: 'POST', htu: saved.target.href, iat: Math.floor(measured.now / 1000),
    jti: randomBytes(16).toString('base64url') };
  if (nonce !== null) claims.nonce = nonce;
  const encodedHeader = Buffer.from(canonical(header), 'utf8').toString('base64url');
  const encodedClaims = Buffer.from(canonical(claims), 'utf8').toString('base64url');
  const signingInput = Buffer.from(`${encodedHeader}.${encodedClaims}`, 'ascii');
  const signature = await saved.key.sign(signingInput, { timeoutMs: remaining(deadline, agentKeyTimeout(saved.key)) });
  return `${encodedHeader}.${encodedClaims}.${Buffer.from(signature).toString('base64url')}`;
}

function oauthError(response, kind) {
  if (response.status !== 400 || !exact(response.body, Object.keys(response.body))
      || Object.keys(response.body).some(key => !ERROR_FIELDS.has(key)) || !Object.hasOwn(response.body, 'error')
      || (Object.hasOwn(response.body, 'error_description')
        && (typeof response.body.error_description !== 'string'
          || Buffer.byteLength(response.body.error_description, 'utf8') > 512))) return null;
  const code = response.body.error;
  if (typeof code !== 'string') return null;
  if (code === 'use_dpop_nonce') return Object.freeze({ challenge: true });
  if (kind === 'device' && (code === 'authorization_pending' || code === 'slow_down')) return Object.freeze({ result: Object.freeze({ state: code }) });
  if (code === 'invalid_grant') return Object.freeze({ error: new AgentError('invalid_grant') });
  if (code === 'expired_token') return Object.freeze({ error: new AgentError('expired_token') });
  if (code === 'access_denied') return Object.freeze({ error: new AgentError('access_denied') });
  if (code === 'invalid_request') return Object.freeze({ error: new AgentError('invalid_request') });
  if (code === 'invalid_dpop_proof') return Object.freeze({ error: new AgentError('invalid_proof') });
  if (code === 'temporarily_unavailable') return Object.freeze({ error: unavailable() });
  return null;
}

function successful(response, expected, submittedRefresh, profile) {
  const body = response.body;
  if (response.status !== 200 || !exact(body, SUCCESS_FIELDS) || body.token_type !== 'DPoP'
      || body.scope !== 'atum:invoke' || !integer(body.expires_in, 1, 60)
      || typeof body.access_token !== 'string' || body.access_token.length > MAX_REQUEST_BYTES || !COMPACT.test(body.access_token)
      || typeof body.refresh_token !== 'string' || !OPAQUE_ARTIFACT.test(body.refresh_token)
      || (submittedRefresh !== null && body.refresh_token === submittedRefresh)) throw unavailable();
  let returned;
  try { returned = authorizationDetails(body.authorization_details, profile); } catch { throw unavailable(); }
  if (canonical(returned) !== canonical(expected)) throw unavailable();
  return snapshotData({ token_type: body.token_type, access_token: body.access_token, expires_in: body.expires_in,
    refresh_token: body.refresh_token, scope: body.scope, authorization_details: returned });
}

export function createTokenClient(config) {
  const saved = configuration(config);
  const transport = createTokenTransport(saved);
  let previousNow;
  let closed = false;
  let active = 0;
  const operations = new Set();

  function readClock() {
    const value = clockSample(saved, previousNow);
    previousNow = value.now;
    return value;
  }

  function run(kind, input) {
    if (closed || active >= saved.maxConcurrent) return Promise.reject(unavailable());
    active += 1;
    const deadline = performance.now() + saved.timeoutMs;
    let captured;
    let liveClock;
    let maximumUpper = -1;
    try {
      captured = operationInput(kind, input, saved.profile);
      captured.form.set('client_id', saved.client_id);
      liveClock = () => {
        const measured = readClock();
        maximumUpper = Math.max(maximumUpper, measured.upper);
        if (maximumUpper >= captured.expected[0].grant_expires_at_ms) throw new AgentError('expired_token');
        return measured;
      };
      liveClock();
    } catch (error) {
      active -= 1;
      return Promise.reject(error instanceof AgentError ? error : invalidRequest());
    }
    return new Promise((resolve, reject) => {
      let settled = false;
      let live = true;
      let resolveCompletion;
      const operation = { completion: new Promise(done => { resolveCompletion = done; }), finish: undefined };
      const finish = (error, result) => {
        if (settled) return;
        settled = true;
        live = false;
        clearTimeout(timer);
        operations.delete(operation);
        active -= 1;
        resolveCompletion();
        if (error) reject(error instanceof AgentError ? error : unavailable()); else resolve(result);
      };
      operation.finish = finish;
      operations.add(operation);
      const timer = setTimeout(() => finish(unavailable()), Math.max(0, deadline - performance.now()));
      (async () => {
        try {
          const firstProof = await dpop(saved, liveClock, null, deadline);
          if (!live || closed || performance.now() >= deadline) throw unavailable();
          liveClock();
          const first = await transport.post(captured.form.toString(), firstProof, deadline);
          if (!live || closed || performance.now() >= deadline) throw unavailable();
          liveClock();
          const firstError = oauthError(first, kind);
          if (firstError?.error) throw firstError.error;
          if (firstError?.result) return finish(null, firstError.result);
          if (!firstError?.challenge || !canonicalBase64(first.dpop_nonce, 32)) throw unavailable();
          const secondProof = await dpop(saved, liveClock, first.dpop_nonce, deadline);
          if (!live || closed || performance.now() >= deadline) throw unavailable();
          liveClock();
          const second = await transport.post(captured.form.toString(), secondProof, deadline);
          if (!live || closed || performance.now() >= deadline) throw unavailable();
          liveClock();
          const secondError = oauthError(second, kind);
          if (secondError?.error) throw secondError.error;
          if (secondError?.result) return finish(null, secondError.result);
          if (secondError?.challenge) throw unavailable();
          finish(null, successful(second, captured.expected, captured.submittedRefresh, saved.profile));
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

  return Object.freeze({
    exchangeCode: input => run('code', input),
    exchangeDevice: input => run('device', input),
    refresh: input => run('refresh', input),
    close,
  });
}
