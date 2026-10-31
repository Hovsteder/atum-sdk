import https from 'node:https';
import tls from 'node:tls';
import { X509Certificate } from 'node:crypto';

import { parseClosedJson, snapshotData } from './strict.mjs';

const MAX_REQUEST_BYTES = 16 * 1024;
const MAX_RESPONSE_BYTES = 32 * 1024;
const MAX_HEADERS = 64;
const MAX_HEADER_BYTES = 16 * 1024;
const MAX_CA_BYTES = 64 * 1024;
const MAX_CA_CERTIFICATES = 8;
const MAX_DPOP_BYTES = 8192;
const PEM_BEGIN = '-----BEGIN CERTIFICATE-----';
const PEM_END = '-----END CERTIFICATE-----';
const PEM_CERTIFICATE = /^-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/]{1,64}={0,2}\r?\n)+-----END CERTIFICATE-----$/;
const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const typedArrayByteLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength').get;

function unavailable() { return new Error('temporarily_unavailable'); }
function invalidConfig() { throw new TypeError('invalid config'); }
function invalidInput() { throw new TypeError('invalid input'); }

function plainRecord(value, fields, invalid) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid();
  let keys; let descriptors;
  try {
    if (Object.getPrototypeOf(value) !== Object.prototype) invalid();
    keys = Reflect.ownKeys(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch { invalid(); }
  if (keys.some(key => typeof key !== 'string') || keys.length !== fields.size || keys.some(key => !fields.has(key))) invalid();
  const copy = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) invalid();
    copy[key] = descriptor.value;
  }
  return copy;
}

function endpoint(value, invalid) {
  if (typeof value !== 'string' || !value.length || /\s|\\/.test(value)) invalid();
  let parsed;
  try { parsed = new URL(value); } catch { invalid(); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash
      || value !== parsed.href || !parsed.pathname || !parsed.hostname) invalid();
  return parsed;
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
  if (count === 0) invalidConfig();
  return value;
}

function configuration(value) {
  const config = plainRecord(value, new Set(['endpoints', 'tls', 'timeoutMs', 'maxConcurrent']), invalidConfig);
  const endpoints = plainRecord(config.endpoints, new Set(['par_url', 'device_authorization_url']), invalidConfig);
  const transportTls = plainRecord(config.tls, new Set(['ca']), invalidConfig);
  if (!Number.isSafeInteger(config.timeoutMs) || config.timeoutMs < 1 || config.timeoutMs > 5000
      || !Number.isSafeInteger(config.maxConcurrent) || config.maxConcurrent < 1 || config.maxConcurrent > 16) invalidConfig();
  const ca = caBundle(transportTls.ca);
  const par = endpoint(endpoints.par_url, invalidConfig);
  const device = endpoint(endpoints.device_authorization_url, invalidConfig);
  if (par.origin !== device.origin) invalidConfig();
  try { tls.createSecureContext({ ca, minVersion: 'TLSv1.2' }); } catch { invalidConfig(); }
  return Object.freeze({
    endpoints: Object.freeze({
      par: Object.freeze({ hostname: par.hostname, port: par.port, host: par.host, path: par.pathname }),
      device: Object.freeze({ hostname: device.hostname, port: device.port, host: device.host, path: device.pathname }),
    }),
    ca,
    timeoutMs: config.timeoutMs,
    maxConcurrent: config.maxConcurrent,
  });
}

function formCopy(value) {
  if (!ArrayBuffer.isView(value) || !(value instanceof Uint8Array)) invalidInput();
  try {
    if (typedArrayByteLength.call(value) > MAX_REQUEST_BYTES) invalidInput();
    return Buffer.from(new Uint8Array(value));
  } catch { invalidInput(); }
}

function dpopHeader(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > MAX_DPOP_BYTES || !COMPACT_JWS.test(value)) invalidInput();
  return value;
}

function responseHeaders(response) {
  const raw = response.rawHeaders;
  if (!Array.isArray(raw) || raw.length % 2 || raw.length / 2 > MAX_HEADERS || Buffer.byteLength(raw.join(''), 'utf8') > MAX_HEADER_BYTES) return null;
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
      || values.get('cache-control') !== 'no-store'
      || typeof length !== 'string' || !/^(0|[1-9][0-9]*)$/.test(length) || Number(length) > MAX_RESPONSE_BYTES) return null;
  return Number(length);
}

function responseValue(response, bytes) {
  const length = responseHeaders(response);
  if (length === null || length !== bytes.length || !Number.isSafeInteger(response.statusCode)
      || response.statusCode < 200 || response.statusCode > 599 || (response.statusCode >= 300 && response.statusCode < 400)) throw unavailable();
  let body;
  try { body = snapshotData(parseClosedJson(bytes, MAX_RESPONSE_BYTES)); } catch { throw unavailable(); }
  return Object.freeze({ status: response.statusCode, body });
}

export function createNativeAuthorizationTransport(config) {
  const saved = configuration(config);
  let agent;
  try {
    agent = new https.Agent({ keepAlive: false, maxSockets: saved.maxConcurrent, maxFreeSockets: 0, maxCachedSessions: 0,
      ca: saved.ca, minVersion: 'TLSv1.2', rejectUnauthorized: true });
  } catch { invalidConfig(); }
  let closed = false;
  let active = 0;
  const operations = new Set();

  function postForm(route, bytes, dpop, deadlineAt) {
    let body; let proof;
    try {
      if (route !== 'par' && route !== 'device') invalidInput();
      body = formCopy(bytes);
      proof = dpopHeader(dpop);
      if (typeof deadlineAt !== 'number' || !Number.isFinite(deadlineAt)) invalidInput();
    } catch (error) { return Promise.reject(error); }
    const startedAt = performance.now();
    if (deadlineAt <= startedAt || deadlineAt > startedAt + saved.timeoutMs) return Promise.reject(new TypeError('invalid input'));
    if (closed || active >= saved.maxConcurrent) return Promise.reject(unavailable());
    active += 1;
    const target = saved.endpoints[route];
    return new Promise((resolve, reject) => {
      let terminal = false;
      let terminalError;
      let terminalValue;
      let released = false;
      let timer;
      let resolveCompletion;
      const operation = { request: null, completion: new Promise(resolveCompletionPromise => { resolveCompletion = resolveCompletionPromise; }) };
      operations.add(operation);
      const record = (error, value) => {
        if (terminal) return;
        terminal = true;
        terminalError = error instanceof Error ? error : null;
        terminalValue = value;
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
        try { operation.request.destroy(unavailable()); } catch { record(unavailable()); }
      };
      const finalize = () => {
        if (!terminal) record(unavailable());
        // Response end can precede a blocking host close callback. Timers alone
        // cannot fence an already latched result while that callback runs.
        if (closed || performance.now() >= deadlineAt) reject(unavailable());
        else if (terminalError) reject(terminalError); else resolve(terminalValue);
        release();
      };
      operation.destroy = () => { record(unavailable()); destroy(); };
      timer = setTimeout(() => { record(unavailable()); destroy(); }, Math.max(0, deadlineAt - performance.now()));
      try {
        const request = https.request({
          protocol: 'https:', hostname: target.hostname, port: target.port || undefined,
          servername: target.hostname, path: target.path, method: 'POST', agent,
          minVersion: 'TLSv1.2', rejectUnauthorized: true,
          headers: { Host: target.host, 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': String(body.length),
            Accept: 'application/json', DPoP: proof, 'Cache-Control': 'no-store', Connection: 'close' },
        }, response => {
          const chunks = []; let size = 0; let complete = false;
          const fail = () => { record(unavailable()); destroy(); };
          if (responseHeaders(response) === null) {
            fail();
            return;
          }
          response.on('data', chunk => {
            size += chunk.length;
            if (size > MAX_RESPONSE_BYTES) {
              fail();
              try { response.destroy(unavailable()); } catch { /* request close releases the slot */ }
            } else chunks.push(chunk);
          });
          response.once('error', fail);
          response.once('aborted', fail);
          response.once('end', () => {
            complete = true;
            try { record(null, responseValue(response, Buffer.concat(chunks))); } catch (error) { record(error); destroy(); }
          });
          response.once('close', () => { if (!complete) fail(); });
        });
        operation.request = request;
        request.once('error', () => record(unavailable()));
        request.once('close', finalize);
        request.end(body);
      } catch {
        record(unavailable());
        if (operation.request) destroy(); else release();
        if (!operation.request) reject(unavailable());
      }
    });
  }

  return Object.freeze({
    postForm,
    async close() {
      if (!closed) {
        closed = true;
        for (const operation of [...operations]) operation.destroy();
        try { agent.destroy(); } catch { /* request close resolves outstanding capacity */ }
      }
      await Promise.all([...operations].map(operation => operation.completion));
    },
  });
}
