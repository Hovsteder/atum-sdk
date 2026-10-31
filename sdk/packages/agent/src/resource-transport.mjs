import https from 'node:https';
import tls from 'node:tls';
import { X509Certificate } from 'node:crypto';

import { AgentError } from './key.mjs';
import { parseClosedJson, snapshotData } from './strict.mjs';

const MAX_BODY_BYTES = 32 * 1024;
const MAX_SECURITY_HEADER_BYTES = 16 * 1024;
const MAX_TOKEN_BYTES = 16 * 1024;
const MAX_DPOP_BYTES = 8 * 1024;
const MAX_HEADERS = 64;
const MAX_HEADER_BYTES = 16 * 1024;
const MAX_CA_BYTES = 64 * 1024;
const MAX_CA_CERTIFICATES = 8;
const PEM_BEGIN = '-----BEGIN CERTIFICATE-----';
const PEM_END = '-----END CERTIFICATE-----';
const PEM_CERTIFICATE = /^-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/]{1,64}={0,2}\r?\n)+-----END CERTIFICATE-----$/;
const COMPACT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const AUTHORIZATION = /^DPoP [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

function unavailable() { return new AgentError('temporarily_unavailable'); }
function invalidRequest() { return new AgentError('invalid_request'); }
function invalidConfig() { throw new TypeError('invalid config'); }

function record(value, fields, invalid, required = fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid();
  let keys; let descriptors;
  try { if (Object.getPrototypeOf(value) !== Object.prototype) invalid(); keys = Reflect.ownKeys(value); descriptors = Object.getOwnPropertyDescriptors(value); } catch { invalid(); }
  if (keys.length > fields.size || keys.some(key => typeof key !== 'string' || !fields.has(key))
      || [...required].some(key => !keys.includes(key))) invalid();
  const copy = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) invalid();
    copy[key] = descriptor.value;
  }
  return copy;
}

function endpoint(value) {
  const source = record(value, new Set(['method', 'url']), invalidConfig);
  if (source.method !== 'POST' || typeof source.url !== 'string' || !source.url.length || /\s|\\|%|\?|#/.test(source.url)) invalidConfig();
  let parsed;
  try { parsed = new URL(source.url); } catch { invalidConfig(); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash || !parsed.hostname || !parsed.pathname || parsed.href !== source.url) invalidConfig();
  return Object.freeze({ method: 'POST', url: source.url, hostname: parsed.hostname, port: parsed.port, host: parsed.host, path: parsed.pathname });
}

function caBundle(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') < 1 || Buffer.byteLength(value, 'utf8') > MAX_CA_BYTES) invalidConfig();
  let offset = 0; let count = 0;
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
  if (!count) invalidConfig();
  return value;
}

function configuration(value) {
  const source = record(value, new Set(['endpoint', 'tls', 'timeoutMs', 'maxConcurrent']), invalidConfig,
    new Set(['endpoint']));
  const timeoutMs = Object.hasOwn(source, 'timeoutMs') ? source.timeoutMs : 5000;
  const maxConcurrent = Object.hasOwn(source, 'maxConcurrent') ? source.maxConcurrent : 4;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 5000 || !Number.isSafeInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 16) invalidConfig();
  let ca;
  if (Object.hasOwn(source, 'tls')) {
    const tlsConfig = record(source.tls, new Set(['ca']), invalidConfig);
    if (Reflect.ownKeys(tlsConfig).length !== 1 || !Object.hasOwn(tlsConfig, 'ca')) invalidConfig();
    ca = caBundle(tlsConfig.ca);
  }
  try { tls.createSecureContext({ ca, minVersion: 'TLSv1.2' }); } catch { invalidConfig(); }
  return Object.freeze({ endpoint: endpoint(source.endpoint), ca, timeoutMs, maxConcurrent });
}

function bodyCopy(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > MAX_BODY_BYTES) throw invalidRequest();
  try { parseClosedJson(value, MAX_BODY_BYTES); return Buffer.from(value, 'utf8'); } catch { throw invalidRequest(); }
}

function security(value, expression, maximum = MAX_SECURITY_HEADER_BYTES) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > maximum || /[\0\r\n]/.test(value) || !expression.test(value)) throw invalidRequest();
  return value;
}

function artifact(value, saved) {
  const source = record(value, new Set(['authorization', 'dpop', 'body', 'method', 'url']), () => { throw invalidRequest(); });
  if (source.method !== saved.endpoint.method || source.url !== saved.endpoint.url) throw invalidRequest();
  return Object.freeze({ authorization: security(source.authorization, AUTHORIZATION, 'DPoP '.length + MAX_TOKEN_BYTES),
    dpop: security(source.dpop, COMPACT, MAX_DPOP_BYTES), body: bodyCopy(source.body) });
}

function headerText(value) {
  return typeof value === 'string' && Buffer.byteLength(value, 'utf8') <= MAX_SECURITY_HEADER_BYTES && !/[\0\r\n]/.test(value) ? value : null;
}

function responseHeaders(response) {
  const raw = response.rawHeaders;
  if (!Array.isArray(raw) || raw.length % 2 || raw.length / 2 > MAX_HEADERS || Buffer.byteLength(raw.join(''), 'utf8') > MAX_HEADER_BYTES) return null;
  const values = new Map();
  for (let index = 0; index < raw.length; index += 2) {
    const name = raw[index]; const value = raw[index + 1];
    if (typeof name !== 'string' || typeof value !== 'string') return null;
    const lowered = name.toLowerCase();
    if (values.has(lowered)) return null;
    values.set(lowered, value);
  }
  const length = values.get('content-length');
  if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(values.get('content-type') ?? '') || values.has('transfer-encoding')
      || values.has('content-encoding') || values.has('set-cookie') || values.get('cache-control') !== 'no-store'
      || typeof length !== 'string' || !/^(0|[1-9][0-9]*)$/.test(length) || Number(length) > MAX_BODY_BYTES) return null;
  const nonce = values.has('dpop-nonce') ? headerText(values.get('dpop-nonce')) : null;
  const authenticate = values.has('www-authenticate') ? headerText(values.get('www-authenticate')) : null;
  if ((values.has('dpop-nonce') && nonce === null) || (values.has('www-authenticate') && authenticate === null)) return null;
  return Object.freeze({ length: Number(length), nonce, authenticate });
}

function responseValue(response, bytes) {
  const headers = responseHeaders(response);
  if (headers === null || headers.length !== bytes.byteLength || !Number.isSafeInteger(response.statusCode) || response.statusCode < 200 || response.statusCode > 599 || (response.statusCode >= 300 && response.statusCode < 400)) throw unavailable();
  let body;
  try { body = snapshotData(parseClosedJson(bytes, MAX_BODY_BYTES)); } catch { throw unavailable(); }
  return Object.freeze({ status: response.statusCode, body, nonce: headers.nonce, authenticate: headers.authenticate });
}

export function createProtectedResourceTransport(config) {
  const saved = configuration(config);
  let agent;
  try { agent = new https.Agent({ keepAlive: false, maxSockets: saved.maxConcurrent, maxFreeSockets: 0, maxCachedSessions: 0, ca: saved.ca, minVersion: 'TLSv1.2', rejectUnauthorized: true }); } catch { invalidConfig(); }
  let closed = false;
  let active = 0;
  const operations = new Set();

  function post(value, deadlineAt) {
    let captured;
    try { captured = artifact(value, saved); if (typeof deadlineAt !== 'number' || !Number.isFinite(deadlineAt)) throw invalidRequest(); } catch (error) { return Promise.reject(error instanceof AgentError ? error : invalidRequest()); }
    const startedAt = performance.now();
    if (deadlineAt <= startedAt || deadlineAt > startedAt + saved.timeoutMs) return Promise.reject(invalidRequest());
    if (closed || active >= saved.maxConcurrent) return Promise.reject(unavailable());
    active += 1;
    return new Promise((resolve, reject) => {
      let terminal = false; let terminalError; let terminalValue; let released = false; let timer;
      let resolveCompletion;
      const operation = { request: null, completion: new Promise(done => { resolveCompletion = done; }) };
      operations.add(operation);
      const record = (error, result) => { if (!terminal) { terminal = true; terminalError = error instanceof Error ? error : null; terminalValue = result; } };
      const release = () => { if (!released) { released = true; clearTimeout(timer); active -= 1; operations.delete(operation); resolveCompletion(); } };
      const destroy = () => { if (operation.request) try { operation.request.destroy(unavailable()); } catch { record(unavailable()); } };
      const finalize = () => {
        if (!terminal) record(unavailable());
        if (closed || performance.now() >= deadlineAt) reject(unavailable());
        else if (terminalError) reject(terminalError); else resolve(terminalValue);
        release();
      };
      operation.destroy = () => { record(unavailable()); destroy(); };
      timer = setTimeout(() => { record(unavailable()); destroy(); }, Math.max(0, deadlineAt - performance.now()));
      try {
        const request = https.request({ protocol: 'https:', hostname: saved.endpoint.hostname, port: saved.endpoint.port || undefined,
          servername: saved.endpoint.hostname, path: saved.endpoint.path, method: 'POST', agent, minVersion: 'TLSv1.2', rejectUnauthorized: true,
          headers: { Host: saved.endpoint.host, 'Content-Type': 'application/json', 'Content-Length': String(captured.body.byteLength), Accept: 'application/json',
            'Cache-Control': 'no-store', Connection: 'close', Authorization: captured.authorization, DPoP: captured.dpop } }, response => {
          const chunks = []; let size = 0; let complete = false;
          const fail = () => { record(unavailable()); destroy(); };
          response.once('error', fail); response.once('aborted', fail);
          response.once('close', () => { if (!complete) fail(); });
          if (responseHeaders(response) === null) return fail();
          response.on('data', chunk => { size += chunk.length; if (size > MAX_BODY_BYTES) { fail(); try { response.destroy(unavailable()); } catch {} } else chunks.push(chunk); });
          response.once('end', () => { complete = true; try { record(null, responseValue(response, Buffer.concat(chunks))); } catch (error) { record(error); destroy(); } });
        });
        operation.request = request;
        request.once('error', () => record(unavailable()));
        request.once('close', finalize);
        request.end(captured.body);
      } catch {
        record(unavailable());
        if (operation.request) destroy(); else { release(); reject(unavailable()); }
      }
    });
  }

  return Object.freeze({ post, async close() {
    if (!closed) { closed = true; for (const operation of [...operations]) operation.destroy(); try { agent.destroy(); } catch {} }
    await Promise.all([...operations].map(operation => operation.completion));
  } });
}
