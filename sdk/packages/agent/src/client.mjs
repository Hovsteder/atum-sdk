import { createHash, randomBytes } from 'node:crypto';
import { addAbortListener } from 'node:events';

import { AgentError, agentKeyTimeout, assertAgentKey } from './key.mjs';
import { createNativeAuthorizationTransport } from './native-authorization.mjs';
import { createRequestProofClient } from './request-proof.mjs';
import { canonical, snapshotData } from './strict.mjs';
import { createTokenClient } from './token.mjs';

const MAX_TIME = 8_640_000_000_000_000;
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const CONFIG_FIELDS = new Set(['registration', 'client', 'endpoints', 'tls', 'key', 'clock', 'timeoutMs', 'maxConcurrent']);
const CODE_BEGIN_FIELDS = new Set(['permissions', 'grant_limit', 'grant_expires_at_ms', 'redirect_uri']);
const DEVICE_BEGIN_FIELDS = new Set(['permissions', 'grant_limit', 'grant_expires_at_ms']);
const REFRESH_FIELDS = new Set(['refresh_token', 'authorization_details']);
const POLL_FIELDS = new Set(['signal']);
const CALLBACK_CODE = /^[A-Za-z0-9_-]{43}$/;
const REQUEST_URI = /^urn:ietf:params:oauth:request_uri:[A-Za-z0-9_-]{43}$/;
const OPAQUE_ARTIFACT = /^[A-Za-z0-9_-]{43}$/;
const USER_CODE = /^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/;
const SIGNAL_ABORTED = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted').get;
const ADD_EVENT_LISTENER = EventTarget.prototype.addEventListener;
const REMOVE_EVENT_LISTENER = EventTarget.prototype.removeEventListener;

function unavailable() { return new AgentError('temporarily_unavailable'); }
function invalidRequest() { throw new AgentError('invalid_request'); }
function expired() { return new AgentError('expired_token'); }
function invalidConfig() { throw new TypeError('invalid config'); }

function record(value, fields, invalid) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid();
  let prototype; let keys; let descriptors;
  try { prototype = Object.getPrototypeOf(value); keys = Reflect.ownKeys(value); descriptors = Object.getOwnPropertyDescriptors(value); } catch { invalid(); }
  if (prototype !== Object.prototype || keys.some(key => typeof key !== 'string' || !fields.has(key)) || keys.length !== Object.keys(descriptors).length) invalid();
  const copy = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) invalid();
    copy[key] = descriptor.value;
  }
  return copy;
}

function exact(value, fields) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));
}

function integer(value, lower, upper = MAX_SAFE) {
  return typeof value === 'number' && Number.isSafeInteger(value) && !Object.is(value, -0) && value >= lower && value <= upper;
}

function snapshot(value, invalid) {
  try { return snapshotData(value); } catch { invalid(); }
}

function configuration(value) {
  const source = record(value, CONFIG_FIELDS, invalidConfig);
  if (!['registration', 'client', 'endpoints', 'tls', 'key', 'clock'].every(field => Object.hasOwn(source, field))
      || (Object.keys(source).length !== 6 && Object.keys(source).length !== 7 && Object.keys(source).length !== 8)
      || typeof source.clock !== 'function') invalidConfig();
  const timeoutMs = Object.hasOwn(source, 'timeoutMs') ? source.timeoutMs : 5000;
  const maxConcurrent = Object.hasOwn(source, 'maxConcurrent') ? source.maxConcurrent : 4;
  if (!integer(timeoutMs, 1, 5000) || !integer(maxConcurrent, 1, 16)) invalidConfig();
  let key;
  try { key = assertAgentKey(source.key); } catch { invalidConfig(); }
  const saved = Object.freeze({ registration: snapshot(source.registration, invalidConfig), client: snapshot(source.client, invalidConfig),
    endpoints: snapshot(source.endpoints, invalidConfig), tls: snapshot(source.tls, invalidConfig), key, clock: source.clock, timeoutMs, maxConcurrent });
  try {
    const validation = createRequestProofClient(saved);
    void validation.close();
  } catch { invalidConfig(); }
  return saved;
}

function clockSample(saved, previous, maximumUpper) {
  let value;
  try { value = snapshotData(saved.clock()); } catch { throw unavailable(); }
  if (!exact(value, ['now_ms', 'uncertainty_ms', 'healthy']) || value.healthy !== true || !integer(value.now_ms, 0, MAX_TIME)
      || !integer(value.uncertainty_ms, 0, 1000) || value.now_ms > MAX_TIME - value.uncertainty_ms
      || (previous !== undefined && value.now_ms < previous)) throw unavailable();
  const upper = value.now_ms + value.uncertainty_ms;
  return Object.freeze({ now: value.now_ms, lower: Math.max(0, value.now_ms - value.uncertainty_ms), upper,
    uncertainty: value.uncertainty_ms, maximumUpper: Math.max(maximumUpper, upper) });
}

function remaining(deadline, maximum) {
  const value = Math.floor(deadline - performance.now());
  if (value < 1) throw unavailable();
  return Math.min(value, maximum);
}

function beginInput(value, fields) {
  const source = record(value, fields, invalidRequest);
  if (!exact(source, [...fields])) invalidRequest();
  return snapshot(source, invalidRequest);
}

function pollInput(value) {
  const source = record(value, POLL_FIELDS, invalidRequest);
  if (!exact(source, [...POLL_FIELDS])) invalidRequest();
  signalAborted(source.signal, invalidRequest);
  return source.signal;
}

function signalAborted(signal, invalid) {
  try { return Reflect.apply(SIGNAL_ABORTED, signal, []); } catch {
    if (invalid) invalid();
    throw unavailable();
  }
}

// Node 22's addAbortListener deliberately installs an unsuppressible listener,
// but performs ordinary property lookups. This private facade forwards its
// internal option symbol to captured intrinsics without reading caller fields.
function abortListenerFacade(signal) {
  return Object.freeze(Object.create(null, {
    aborted: { enumerable: true, get: () => signalAborted(signal) },
    addEventListener: { enumerable: true, value: (...args) => Reflect.apply(ADD_EVENT_LISTENER, signal, args) },
    removeEventListener: { enumerable: true, value: (...args) => Reflect.apply(REMOVE_EVENT_LISTENER, signal, args) },
  }));
}

function refreshInput(value) {
  const source = record(value, REFRESH_FIELDS, invalidRequest);
  if (!exact(source, [...REFRESH_FIELDS]) || typeof source.refresh_token !== 'string') invalidRequest();
  return Object.freeze({ refresh_token: source.refresh_token, authorization_details: snapshot(source.authorization_details, invalidRequest) });
}

function random32() {
  try { return randomBytes(32).toString('base64url'); } catch { throw unavailable(); }
}

async function nativeDpop(saved, readClock, deadline, url) {
  const initial = readClock();
  const header = { alg: 'ES256', typ: 'dpop+jwt', jwk: saved.key.publicJwk };
  const claims = { htm: 'POST', htu: url, iat: Math.floor(initial.now / 1000), jti: randomBytes(16).toString('base64url') };
  const encodedHeader = Buffer.from(canonical(header), 'utf8').toString('base64url');
  const encodedClaims = Buffer.from(canonical(claims), 'utf8').toString('base64url');
  const signature = await saved.key.sign(Buffer.from(`${encodedHeader}.${encodedClaims}`, 'ascii'),
    { timeoutMs: remaining(deadline, agentKeyTimeout(saved.key)) });
  if (performance.now() >= deadline) throw unavailable();
  readClock();
  return `${encodedHeader}.${encodedClaims}.${Buffer.from(signature).toString('base64url')}`;
}

function expectedAuthorizationDetails(request) {
  return snapshotData([{ type: 'atum', permissions: request.permissions, grant_limit: request.grant_limit,
    grant_expires_at_ms: request.grant_expires_at_ms }]);
}

function parForm(saved, prepared) {
  const request = prepared.request;
  return Buffer.from(new URLSearchParams([
    ['atum_request', prepared.atum_request], ['authorization_details', canonical(expectedAuthorizationDetails(request))],
    ['client_id', saved.client.client_id], ['code_challenge', request.code.code_challenge], ['code_challenge_method', 'S256'],
    ['dpop_jkt', saved.key.thumbprint], ['redirect_uri', request.code.redirect_uri], ['resource', request.resource],
    ['response_type', 'code'], ['scope', 'atum:invoke'], ['state', request.code.state],
  ]).toString(), 'utf8');
}

function deviceForm(saved, prepared) {
  const request = prepared.request;
  return Buffer.from(new URLSearchParams([
    ['atum_request', prepared.atum_request], ['authorization_details', canonical(expectedAuthorizationDetails(request))],
    ['client_id', saved.client.client_id], ['resource', request.resource], ['scope', 'atum:invoke'],
  ]).toString(), 'utf8');
}

function parResponse(value) {
  if (!exact(value, ['request_uri', 'expires_in']) || typeof value.request_uri !== 'string' || !REQUEST_URI.test(value.request_uri)
      || !integer(value.expires_in, 1, 60)) throw unavailable();
  return Object.freeze({ request_uri: value.request_uri, expires_in: value.expires_in });
}

function authorizationUrl(saved, requestUri) {
  const url = new URL(saved.endpoints.authorization_url);
  url.search = new URLSearchParams([['client_id', saved.client.client_id], ['request_uri', requestUri]]).toString();
  return url.href;
}

function deviceResponse(value, saved) {
  const fields = Object.hasOwn(value ?? {}, 'interval')
    ? ['device_code', 'user_code', 'verification_uri', 'verification_uri_complete', 'expires_in', 'interval']
    : ['device_code', 'user_code', 'verification_uri', 'verification_uri_complete', 'expires_in'];
  if (!exact(value, fields) || typeof value.device_code !== 'string' || !OPAQUE_ARTIFACT.test(value.device_code)
      || typeof value.user_code !== 'string' || !USER_CODE.test(value.user_code)
      || !integer(value.expires_in, 1, 300)
      || (Object.hasOwn(value, 'interval') && !integer(value.interval, 1, 300))) throw unavailable();
  let issuer; let verification; let complete;
  try {
    issuer = new URL(saved.registration.issuer);
    verification = new URL(value.verification_uri);
    complete = new URL(value.verification_uri_complete);
  } catch { throw unavailable(); }
  if (typeof value.verification_uri !== 'string' || typeof value.verification_uri_complete !== 'string'
      || value.verification_uri.includes('?') || value.verification_uri.includes('#')
      || value.verification_uri_complete.includes('#')
      || verification.href !== value.verification_uri || complete.href !== value.verification_uri_complete
      || verification.protocol !== 'https:' || verification.origin !== issuer.origin || complete.origin !== issuer.origin
      || verification.username || verification.password || verification.search || verification.hash
      || complete.username || complete.password || complete.hash || complete.pathname !== verification.pathname) throw unavailable();
  const expectedComplete = new URL(verification.href);
  expectedComplete.search = new URLSearchParams([['user_code', value.user_code]]).toString();
  if (complete.href !== expectedComplete.href) throw unavailable();
  return Object.freeze({ device_code: value.device_code, user_code: value.user_code,
    verification_uri: verification.href, verification_uri_complete: complete.href,
    expires_in: value.expires_in, interval_ms: (value.interval ?? 5) * 1000 });
}

function callbackData(value, saved, redirectUri, state) {
  if (typeof value !== 'string' || !value.length || Buffer.byteLength(value, 'utf8') > 4096 || value.includes('#') || /\s|\\/.test(value)) throw invalidRequest();
  let callback; let redirect;
  try { callback = new URL(value); redirect = new URL(redirectUri); } catch { throw invalidRequest(); }
  if (callback.protocol !== redirect.protocol || callback.hostname !== redirect.hostname || callback.port !== redirect.port
      || callback.pathname !== redirect.pathname || callback.username || callback.password || callback.hash) throw invalidRequest();
  const entries = [...callback.searchParams];
  const values = Object.create(null);
  for (const [key, entry] of entries) {
    if (Object.hasOwn(values, key)) throw invalidRequest();
    values[key] = entry;
  }
  const base = values.state === state && values.iss === saved.registration.issuer;
  if (!base) throw invalidRequest();
  const keys = Object.keys(values).sort();
  if (keys.join(',') === 'code,iss,state' && CALLBACK_CODE.test(values.code)) return Object.freeze({ kind: 'code', code: values.code });
  if ((keys.join(',') === 'error,iss,state' || keys.join(',') === 'error,error_description,iss,state') && values.error === 'access_denied') {
    if (Object.hasOwn(values, 'error_description') && (typeof values.error_description !== 'string' || Buffer.byteLength(values.error_description, 'utf8') > 512)) throw invalidRequest();
    return Object.freeze({ kind: 'cancelled' });
  }
  throw invalidRequest();
}

export async function createAgentClient(config) {
  const saved = configuration(config);
  const transport = createNativeAuthorizationTransport({ endpoints: { par_url: saved.endpoints.par_url,
    device_authorization_url: saved.endpoints.device_authorization_url }, tls: saved.tls, timeoutMs: saved.timeoutMs, maxConcurrent: saved.maxConcurrent });
  let previousNow;
  let maximumUpper = -1;
  let closed = false;
  let active = 0;
  const operations = new Set();
  const polls = new Set();

  function readClock() {
    const value = clockSample(saved, previousNow, maximumUpper);
    previousNow = value.now;
    maximumUpper = value.maximumUpper;
    return value;
  }

  function childClock(operation, originalExpiry, cancelled) {
    let originalExpired = false;
    const measured = () => {
      if (!operation.live() || cancelled?.()) throw unavailable();
      const value = readClock();
      if (value.maximumUpper >= originalExpiry) {
        originalExpired = true;
        throw expired();
      }
      return value;
    };
    return Object.freeze({
      clock: () => {
        const value = measured();
        return Object.freeze({ healthy: true, now_ms: value.now, uncertainty_ms: value.uncertainty });
      },
      measured,
      originalExpired: () => originalExpired,
    });
  }

  function run(work) {
    if (closed || active >= saved.maxConcurrent) return Promise.reject(unavailable());
    active += 1;
    const deadline = performance.now() + saved.timeoutMs;
    return new Promise((resolve, reject) => {
      let settled = false;
      let live = true;
      let resolveCompletion;
      const children = new Set();
      const operation = { children, completion: new Promise(done => { resolveCompletion = done; }), finish: undefined };
      const closeChildren = async () => { await Promise.all([...children].map(async child => { try { await child.close(); } catch { /* child failures are already redacted */ } })); };
      const finish = (error, result) => {
        if (settled) return;
        if (!error && (closed || performance.now() >= deadline)) error = unavailable();
        settled = true; live = false; clearTimeout(timer); active -= 1; operations.delete(operation);
        void closeChildren().then(resolveCompletion);
        if (error) reject(error instanceof AgentError ? error : unavailable()); else resolve(result);
      };
      operation.finish = finish;
      operations.add(operation);
      const timer = setTimeout(() => finish(unavailable()), Math.max(0, deadline - performance.now()));
      (async () => {
        try { finish(null, await work({ deadline, children, live: () => live && !closed && performance.now() < deadline })); }
        catch (error) { finish(error); }
      })();
    });
  }

  async function tokenOperation(operation, kind, input, originalExpiry, control) {
    const before = readClock();
    if (before.maximumUpper >= originalExpiry) throw expired();
    if (control?.cancelled()) throw unavailable();
    const sharedClock = childClock(operation, originalExpiry, control?.cancelled);
    const child = createTokenClient({ client_id: saved.client.client_id, token_url: saved.endpoints.token_url, tls: saved.tls,
      key: saved.key, clock: sharedClock.clock, timeoutMs: remaining(operation.deadline, saved.timeoutMs), maxConcurrent: 1 });
    operation.children.add(child);
    let result;
    try {
      if (control?.attachChild(child) === false) throw unavailable();
      result = await (kind === 'code' ? child.exchangeCode(input)
        : kind === 'device' ? child.exchangeDevice(input) : child.refresh(input));
    } catch (error) {
      if (sharedClock.originalExpired()) throw expired();
      throw error;
    } finally {
      operation.children.delete(child);
      await child.close();
    }
    if (!operation.live() || control?.cancelled()) throw unavailable();
    const after = readClock();
    if (after.maximumUpper >= originalExpiry) throw expired();
    return result;
  }

  function beginAuthorizationCode(value) {
    let input;
    try { input = beginInput(value, CODE_BEGIN_FIELDS); } catch (error) { return Promise.reject(error); }
    return run(async operation => {
      const initial = readClock();
      if (initial.maximumUpper >= input.grant_expires_at_ms) throw expired();
      const verifier = random32();
      const state = random32();
      const challenge = createHash('sha256').update(verifier, 'ascii').digest('base64url');
      const sharedClock = childClock(operation, input.grant_expires_at_ms);
      const preparation = createRequestProofClient({ ...saved, clock: sharedClock.clock,
        timeoutMs: remaining(operation.deadline, saved.timeoutMs), maxConcurrent: 1 });
      operation.children.add(preparation);
      let prepared;
      try {
        prepared = await preparation.prepare({ flow: 'authorization_code', permissions: input.permissions, grant_limit: input.grant_limit,
          grant_expires_at_ms: input.grant_expires_at_ms, redirect_uri: input.redirect_uri, code_challenge: challenge, state });
      } catch (error) {
        if (sharedClock.originalExpired()) throw expired();
        throw error;
      } finally {
        operation.children.delete(preparation);
        await preparation.close();
      }
      if (!operation.live()) throw unavailable();
      const afterPrepare = readClock();
      if (afterPrepare.maximumUpper >= prepared.expires_at_ms) throw expired();
      const parClock = childClock(operation, prepared.expires_at_ms);
      let proof;
      try {
        proof = await nativeDpop(saved, parClock.measured, operation.deadline, saved.endpoints.par_url);
      } catch (error) {
        if (parClock.originalExpired()) throw expired();
        throw error;
      }
      if (!operation.live()) throw unavailable();
      const beforePar = readClock();
      if (beforePar.maximumUpper >= prepared.expires_at_ms) throw expired();
      const response = await transport.postForm('par', parForm(saved, prepared), proof, operation.deadline);
      if (!operation.live()) throw unavailable();
      const afterPar = readClock();
      if (response.status !== 201 || afterPar.maximumUpper >= prepared.expires_at_ms) throw unavailable();
      const par = parResponse(response.body);
      const retrievalExpiresAt = Math.min(beforePar.lower + par.expires_in * 1000, prepared.expires_at_ms);
      if (afterPar.maximumUpper >= retrievalExpiresAt) throw unavailable();
      let used = false;
      const completeCallback = async callback => {
        if (used) throw invalidRequest();
        used = true;
        if (closed) throw unavailable();
        let parsed;
        try { parsed = callbackData(callback, saved, input.redirect_uri, state); } catch (error) { throw error instanceof AgentError ? error : invalidRequest(); }
        if (parsed.kind === 'cancelled') throw new AgentError('access_denied');
        return run(async tokenRun => tokenOperation(tokenRun, 'code', { code: parsed.code, code_verifier: verifier,
          redirect_uri: input.redirect_uri, expected_authorization_details: expectedAuthorizationDetails(prepared.request) }, prepared.expires_at_ms));
      };
      return Object.freeze({ authorization_url: authorizationUrl(saved, par.request_uri), request_id: prepared.request.request_id,
        expires_at_ms: prepared.expires_at_ms, completeCallback });
    });
  }

  function beginDeviceAuthorization(value) {
    let input;
    try { input = beginInput(value, DEVICE_BEGIN_FIELDS); } catch (error) { return Promise.reject(error); }
    return run(async operation => {
      const initial = readClock();
      if (initial.maximumUpper >= input.grant_expires_at_ms) throw expired();
      const sharedClock = childClock(operation, input.grant_expires_at_ms);
      const preparation = createRequestProofClient({ ...saved, clock: sharedClock.clock,
        timeoutMs: remaining(operation.deadline, saved.timeoutMs), maxConcurrent: 1 });
      operation.children.add(preparation);
      let prepared;
      try {
        prepared = await preparation.prepare({ flow: 'device_code', permissions: input.permissions,
          grant_limit: input.grant_limit, grant_expires_at_ms: input.grant_expires_at_ms });
      } catch (error) {
        if (sharedClock.originalExpired()) throw expired();
        throw error;
      } finally {
        operation.children.delete(preparation);
        await preparation.close();
      }
      if (!operation.live()) throw unavailable();
      const afterPrepare = readClock();
      if (afterPrepare.maximumUpper >= prepared.expires_at_ms) throw expired();
      const nativeClock = childClock(operation, prepared.expires_at_ms);
      let proof;
      try {
        proof = await nativeDpop(saved, nativeClock.measured, operation.deadline, saved.endpoints.device_authorization_url);
      } catch (error) {
        if (nativeClock.originalExpired()) throw expired();
        throw error;
      }
      if (!operation.live()) throw unavailable();
      const beforeDevice = readClock();
      if (beforeDevice.maximumUpper >= prepared.expires_at_ms) throw expired();
      const response = await transport.postForm('device', deviceForm(saved, prepared), proof, operation.deadline);
      if (!operation.live()) throw unavailable();
      const afterDevice = readClock();
      if (response.status !== 200) throw unavailable();
      const native = deviceResponse(response.body, saved);
      if (native.expires_in > Math.floor((MAX_TIME - beforeDevice.lower) / 1000)) throw unavailable();
      const expiresAt = Math.min(beforeDevice.lower + native.expires_in * 1000, prepared.expires_at_ms);
      if (afterDevice.maximumUpper >= expiresAt) throw expired();
      const expected = expectedAuthorizationDetails(prepared.request);
      let used = false;

      const poll = value => {
        let signal;
        try { signal = pollInput(value); } catch (error) { return Promise.reject(error); }
        if (used) return Promise.reject(new AgentError('invalid_request'));
        used = true;
        if (closed || signalAborted(signal)) return Promise.reject(unavailable());
        let intervalMs = native.interval_ms;
        return new Promise((resolve, reject) => {
          let settled = false;
          let timer;
          let cancelAttempt;
          let abortSubscription;
          const finish = (error, result) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            if (cancelAttempt) { const cancel = cancelAttempt; cancelAttempt = undefined; cancel(); }
            try { abortSubscription?.[Symbol.dispose](); } catch { error = unavailable(); }
            polls.delete(polling);
            if (error) reject(error instanceof AgentError ? error : unavailable()); else resolve(result);
          };
          const abort = () => finish(unavailable());
          const schedule = () => {
            if (settled || closed || signalAborted(signal)) return finish(unavailable());
            let measured;
            try { measured = readClock(); } catch (error) { return finish(error); }
            if (measured.maximumUpper >= expiresAt) return finish(expired());
            const waitMs = Math.min(intervalMs, expiresAt - measured.maximumUpper);
            timer = setTimeout(() => attempt(intervalMs - waitMs), waitMs);
          };
          const attempt = intervalRemaining => {
            timer = undefined;
            if (settled || closed || signalAborted(signal)) return finish(unavailable());
            let measured;
            try { measured = readClock(); } catch (error) { return finish(error); }
            if (measured.maximumUpper >= expiresAt) return finish(expired());
            if (intervalRemaining > 0) {
              const waitMs = Math.min(intervalRemaining, expiresAt - measured.maximumUpper);
              timer = setTimeout(() => attempt(intervalRemaining - waitMs), waitMs);
              return;
            }
            run(tokenRun => tokenOperation(tokenRun, 'device', { device_code: native.device_code,
              expected_authorization_details: expected }, expiresAt, {
              cancelled: () => settled || closed || signalAborted(signal),
              attachChild: child => {
                cancelAttempt = () => { void child.close(); };
                if (settled || closed || signalAborted(signal)) { cancelAttempt(); return false; }
                return true;
              },
            })).then(result => {
              cancelAttempt = undefined;
              if (settled || closed || signalAborted(signal)) return finish(unavailable());
              if (result?.state === 'authorization_pending') return schedule();
              if (result?.state === 'slow_down') {
                if (intervalMs > MAX_SAFE - 5000) return finish(unavailable());
                intervalMs += 5000; return schedule();
              }
              finish(null, result);
            }, error => { cancelAttempt = undefined; finish(error); });
          };
          const polling = Object.freeze({ cancel: abort });
          polls.add(polling);
          try { abortSubscription = addAbortListener(abortListenerFacade(signal), abort); }
          catch { return finish(unavailable()); }
          schedule();
        });
      };

      return Object.freeze({ verification_uri: native.verification_uri,
        verification_uri_complete: native.verification_uri_complete, user_code: native.user_code,
        request_id: prepared.request.request_id, expires_at_ms: expiresAt,
        interval_ms: native.interval_ms, poll });
    });
  }

  function refresh(value) {
    let input;
    try { input = refreshInput(value); } catch (error) { return Promise.reject(error); }
    let expiry;
    try {
      const detail = input.authorization_details;
      if (!Array.isArray(detail) || detail.length !== 1 || !exact(detail[0], ['type', 'permissions', 'grant_limit', 'grant_expires_at_ms'])
          || detail[0].type !== 'atum' || !integer(detail[0].grant_expires_at_ms, 1, MAX_TIME)) throw invalidRequest();
      expiry = detail[0].grant_expires_at_ms;
    } catch (error) { return Promise.reject(error instanceof AgentError ? error : invalidRequest()); }
    return run(operation => tokenOperation(operation, 'refresh', { refresh_token: input.refresh_token,
      expected_authorization_details: input.authorization_details }, expiry));
  }

  return Object.freeze({
    beginAuthorizationCode,
    beginDeviceAuthorization,
    refresh,
    async close() {
      if (!closed) {
        closed = true;
        for (const polling of [...polls]) polling.cancel();
        const pending = [...operations];
        for (const operation of pending) operation.finish(unavailable());
        await transport.close();
        await Promise.all(pending.map(operation => operation.completion));
        return;
      }
      await transport.close();
    },
  });
}
