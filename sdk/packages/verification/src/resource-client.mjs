import https from 'node:https';
import tls from 'node:tls';
import { parseStrictJson, validateBoundIntent } from './context.mjs';
import { validateResourceRegistration } from './resource-profiles.mjs';

const MAX_BODY = 32768;
const MAX_RESPONSE = 65536;
const SAFE_ERRORS = new Map([
  [400, new Set(['invalid_request'])], [401, new Set(['invalid_proof'])],
  [403, new Set(['unauthorized_resource'])], [404, new Set(['not_found'])],
  [409, new Set(['conflict'])], [410, new Set(['expired'])],
  [422, new Set(['grant_not_active', 'grant_expired', 'account_not_bound', 'evidence_insufficient'])],
  [503, new Set(['temporarily_unavailable'])],
]);
const CLIENT_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const METHODS = Object.freeze({
  snapshot: '/v1/authority/grant-snapshot',
  admit: '/v1/authority/admissions',
  retrieve: '/v1/authority/admissions/retrieve',
});
const SERVICE_METHODS = Object.freeze({
  snapshot: '/v1/service/authority/grant-snapshot',
  admit: '/v1/service/authority/admissions',
  retrieve: '/v1/service/authority/admissions/retrieve',
});

export class ResourceTransportError extends Error {
  constructor(code) { super(code); this.name = 'ResourceTransportError'; this.code = code; }
}

function unavailable() { return new ResourceTransportError('temporarily_unavailable'); }
function invalid() { return new ResourceTransportError('invalid_request'); }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, fields) { return plain(value) && Object.keys(value).length === fields.size && Object.keys(value).every(key => fields.has(key)); }
function frozenCopy(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(frozenCopy));
  if (plain(value)) return Object.freeze(Object.fromEntries(Object.entries(value).map(([key, item]) => [key, frozenCopy(item)])));
  return value;
}
function validRegistration(value, descriptor) {
  try { validateResourceRegistration(value, descriptor); return true; } catch { return false; }
}

function configCopy(config) {
  const credentialMode = Object.hasOwn(config ?? {}, 'serviceCredential');
  const fields = new Set(['baseUrl', 'registration', credentialMode ? 'https' : 'tls', 'timeoutMs', 'maxConcurrent']);
  if (credentialMode) fields.add('serviceCredential');
  if (Object.hasOwn(config ?? {}, 'descriptor')) fields.add('descriptor');
  const transport = credentialMode ? config.https : config.tls;
  if (!exact(config, fields) || !plain(transport)
      || typeof config.baseUrl !== 'string'
      || (!credentialMode && (!exact(transport, new Set(['ca', 'cert', 'key'])) || [transport.ca, transport.cert, transport.key].some(value => typeof value !== 'string' || !value.length)))
      || (credentialMode && (!exact(transport, Object.hasOwn(transport, 'ca') ? new Set(['ca']) : new Set())
        || (Object.hasOwn(transport, 'ca') && (typeof transport.ca !== 'string' || !transport.ca.length))
        || typeof config.serviceCredential !== 'string' || !/^atum_svc_[A-Za-z0-9_-]{43}$/.test(config.serviceCredential)))
      || !Number.isSafeInteger(config.timeoutMs) || config.timeoutMs < 1 || config.timeoutMs > 10000
      || !Number.isSafeInteger(config.maxConcurrent) || config.maxConcurrent < 1 || config.maxConcurrent > 16) throw new TypeError('invalid config');
  let base;
  try {
    if (/\\s|\\\\/.test(config.baseUrl)) throw new TypeError('invalid config');
    base = new URL(config.baseUrl);
    if (base.protocol !== 'https:' || config.baseUrl !== base.origin && config.baseUrl !== `${base.origin}/`) throw new TypeError('invalid config');
    tls.createSecureContext({ ...(Object.hasOwn(transport, 'ca') ? { ca: transport.ca } : {}), ...(credentialMode ? {} : { cert: transport.cert, key: transport.key }), minVersion: 'TLSv1.2' });
  } catch { throw new TypeError('invalid config'); }
  try {
    const registration = structuredClone(config.registration);
    const descriptor = Object.hasOwn(config, 'descriptor') ? structuredClone(config.descriptor) : undefined;
    if (!validRegistration(registration, descriptor)) throw new TypeError('invalid config');
    return frozenCopy({ baseUrl: base.href, hostname: base.hostname, port: base.port, registration, descriptor,
      transport: structuredClone(transport), credential: credentialMode ? config.serviceCredential : null,
      timeoutMs: config.timeoutMs, maxConcurrent: config.maxConcurrent });
  } catch { throw new TypeError('invalid config'); }
}

function requestCopy(input, registration, descriptor) {
  if (!exact(input, new Set(['context', 'action_request', 'client_id'])) || typeof input.client_id !== 'string' || !CLIENT_ID.test(input.client_id)) throw invalid();
  let copy;
  try { copy = structuredClone(input); validateBoundIntent(copy.context, copy.action_request, registration, descriptor); } catch { throw invalid(); }
  let body;
  try { body = Buffer.from(JSON.stringify(copy), 'utf8'); } catch { throw invalid(); }
  if (body.length > MAX_BODY) throw invalid();
  return Object.freeze({ body, clientId: copy.client_id });
}

function contentType(value) { return typeof value === 'string' && /^application\/json(?:;\s*charset=utf-8)?$/i.test(value); }
function oneHeader(rawHeaders, name) {
  const values = [];
  for (let i = 0; i < rawHeaders.length; i += 2) if (rawHeaders[i].toLowerCase() === name) values.push(rawHeaders[i + 1]);
  return values.length === 1 ? values[0] : null;
}
function validHeaders(response) {
  if (!Array.isArray(response.rawHeaders) || response.rawHeaders.length / 2 > 64 || Buffer.byteLength(response.rawHeaders.join(''), 'utf8') > 16384) return false;
  const names = new Set();
  for (let i = 0; i < response.rawHeaders.length; i += 2) { const name = response.rawHeaders[i].toLowerCase(); if (names.has(name)) return false; names.add(name); }
  const length = oneHeader(response.rawHeaders, 'content-length');
  return contentType(oneHeader(response.rawHeaders, 'content-type')) && oneHeader(response.rawHeaders, 'transfer-encoding') === null
    && oneHeader(response.rawHeaders, 'content-encoding') === null && oneHeader(response.rawHeaders, 'set-cookie') === null
    && oneHeader(response.rawHeaders, 'cache-control') === 'no-store' && typeof length === 'string' && /^(0|[1-9][0-9]*)$/.test(length) && Number(length) <= MAX_RESPONSE;
}
function resultFor(response, bytes) {
  if (!validHeaders(response) || Number(oneHeader(response.rawHeaders, 'content-length')) !== bytes.length) throw unavailable();
  let body;
  try { body = parseStrictJson(bytes, MAX_RESPONSE); } catch { throw unavailable(); }
  if (response.statusCode === 200) {
    if (!exact(body, new Set(['assertion'])) || typeof body.assertion !== 'string' || !body.assertion.length || body.assertion.length > MAX_BODY || !COMPACT_JWS.test(body.assertion) || /[^\x21-\x7e]/.test(body.assertion)) throw unavailable();
    return body.assertion;
  }
  const permitted = SAFE_ERRORS.get(response.statusCode);
  if (!permitted || !exact(body, new Set(['error'])) || !exact(body.error, new Set(['code'])) || typeof body.error.code !== 'string' || !permitted.has(body.error.code)) throw unavailable();
  throw new ResourceTransportError(body.error.code);
}

export function createResourceClient(config) {
  const saved = configCopy(config);
  let agent;
  try { agent = new https.Agent({ keepAlive: true, maxSockets: saved.maxConcurrent, maxFreeSockets: 0, maxCachedSessions: 0,
    ...(Object.hasOwn(saved.transport, 'ca') ? { ca: saved.transport.ca } : {}), ...(saved.credential === null ? { cert: saved.transport.cert, key: saved.transport.key } : {}),
    minVersion: 'TLSv1.2', rejectUnauthorized: true }); } catch { throw new TypeError('invalid config'); }
  let closed = false;
  let active = 0;
  const operations = new Set();

  function call(route, input) {
    let request;
    try { request = requestCopy(input, saved.registration, saved.descriptor); } catch (error) { return Promise.reject(error instanceof ResourceTransportError ? error : invalid()); }
    if (closed || active >= saved.maxConcurrent) return Promise.reject(unavailable());
    active += 1;
    return new Promise((resolve, reject) => {
      let done = false;
      let released = false;
      let timer;
      let resolveCompletion;
      const operation = { request: null, completion: new Promise(resolveCompletionPromise => { resolveCompletion = resolveCompletionPromise; }) };
      operations.add(operation);
      const finish = (error, value) => {
        if (done) return; done = true;
        if (error) reject(error instanceof ResourceTransportError ? error : unavailable()); else resolve(value);
      };
      const release = () => {
        if (released) return;
        released = true;
        clearTimeout(timer);
        active -= 1;
        operations.delete(operation);
        resolveCompletion();
      };
      const destroy = () => {
        if (!operation.request) return;
        try { operation.request.destroy(unavailable()); } catch { finish(unavailable()); }
      };
      operation.destroy = () => { finish(unavailable()); destroy(); };
      timer = setTimeout(() => { finish(unavailable()); destroy(); }, saved.timeoutMs);
      try {
          const req = https.request({ protocol: 'https:', hostname: saved.hostname, port: saved.port || undefined, servername: saved.hostname, path: route, method: 'POST', agent, minVersion: 'TLSv1.2', rejectUnauthorized: true, headers: { Host: saved.port ? `${saved.hostname}:${saved.port}` : saved.hostname, 'Content-Type': 'application/json', 'Content-Length': String(request.body.length), Accept: 'application/json', 'Cache-Control': 'no-store', ...(saved.credential === null ? {} : { Authorization: `Bearer ${saved.credential}` }) } }, (res) => {
          const chunks = []; let size = 0; let responseComplete = false;
          const failResponse = () => { finish(unavailable()); destroy(); };
          res.on('data', chunk => {
            size += chunk.length;
            if (size > MAX_RESPONSE) { failResponse(); try { res.destroy(unavailable()); } catch { /* request close releases the slot */ } } else chunks.push(chunk);
          });
          res.once('error', failResponse);
          res.once('aborted', failResponse);
          res.once('end', () => {
            responseComplete = true;
            try { finish(null, resultFor(res, Buffer.concat(chunks))); } catch (error) { finish(error); }
            release();
          });
          res.once('close', () => { if (!responseComplete) failResponse(); });
        });
        operation.request = req;
        req.once('error', () => finish(unavailable()));
        req.once('close', () => { finish(unavailable()); release(); });
        req.end(request.body);
      } catch {
        finish(unavailable());
        if (operation.request) destroy(); else release();
      }
    });
  }
  return Object.freeze({
    snapshot(input) { return call((saved.credential === null ? METHODS : SERVICE_METHODS).snapshot, input); },
    admit(input) { return call((saved.credential === null ? METHODS : SERVICE_METHODS).admit, input); },
    retrieve(input) { return call((saved.credential === null ? METHODS : SERVICE_METHODS).retrieve, input); },
    async close() {
      if (!closed) {
        closed = true;
        for (const operation of [...operations]) operation.destroy();
        try { agent.destroy(); } catch { /* active operations still resolve from their close events */ }
      }
      await Promise.all([...operations].map(operation => operation.completion));
    },
  });
}
