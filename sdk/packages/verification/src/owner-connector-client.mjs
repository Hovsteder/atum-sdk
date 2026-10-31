import https from 'node:https';
import tls from 'node:tls';
import { visit } from 'jsonc-parser';
import { parseStrictJson } from './context.mjs';

const MAX_BODY = 98304;
const MAX_RESPONSE = 131072;
const SAFE_ERRORS = new Map([
  [400, new Set(['invalid_request'])], [401, new Set(['invalid_proof'])],
  [403, new Set(['unauthorized_resource'])], [404, new Set(['not_found'])],
  [409, new Set(['conflict', 'already_consumed'])], [410, new Set(['expired'])],
  [503, new Set(['temporarily_unavailable'])],
]);
const ID = /^[A-Za-z0-9._:-]{1,128}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const CONTEXT = ['issuer','audience','environment','tenant_id','resource_id','quota_scope_id'];
const INPUTS = Object.freeze({open:['flow_id','channel_id','expires_at_ms'], pair:['flow_id','return_handle'], reservation:['flow_id','reservation'], confirmation:['flow_id','resource_confirmation'], outcome:['flow_id','outcome'], read:['flow_id']});
const METHODS = Object.freeze(Object.fromEntries(Object.keys(INPUTS).map(name => [name, `/v1/owner-connector/${name}`])));
const MATERIAL = ['reservation','statement','resource_confirmation','activation_receipt','outcome'];
const PHASES = Object.freeze({offered:0,claimed:0,paired:0,reserved:1,prepared:2,confirmed:3,awaiting_resource:4,ready:5,cancelled:5,retired:5});

export class OwnerConnectorTransportError extends Error {
  constructor(code) { super(code); this.name = 'OwnerConnectorTransportError'; this.code = code; }
}

function unavailable() { return new OwnerConnectorTransportError('temporarily_unavailable'); }
function invalid() { return new OwnerConnectorTransportError('invalid_request'); }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, fields) { return plain(value) && Object.keys(value).length === fields.size && Object.keys(value).every(key => fields.has(key)); }
function frozenCopy(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(frozenCopy));
  if (plain(value)) return Object.freeze(Object.fromEntries(Object.entries(value).map(([key, item]) => [key, frozenCopy(item)])));
  return value;
}
function validRegistration(value) {
  const party = /^[A-Za-z0-9:/._-]{1,256}$/;
  return exact(value,new Set(CONTEXT)) && ['issuer','audience'].every(key => typeof value[key] === 'string' && party.test(value[key]))
    && value.environment === 'sandbox' && ['tenant_id','resource_id','quota_scope_id'].every(key => typeof value[key] === 'string' && ID.test(value[key]));
}
function isTime(value) { return Number.isSafeInteger(value) && !Object.is(value,-0) && value >= 0 && value <= 8640000000000000; }
function isHandle(value) { return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value) && Buffer.from(value,'base64url').length === 32 && Buffer.from(value,'base64url').toString('base64url') === value; }
function isCompact(value) { return typeof value === 'string' && value.length <= 32768 && COMPACT_JWS.test(value); }

function configCopy(config) {
  if (!exact(config, new Set(['baseUrl', 'registration', 'tls', 'timeoutMs', 'maxConcurrent'])) || !plain(config.tls)
      || typeof config.baseUrl !== 'string' || !exact(config.tls, new Set(['ca', 'cert', 'key'])) || [config.tls.ca, config.tls.cert, config.tls.key].some(value => typeof value !== 'string' || !value.length)
      || !Number.isSafeInteger(config.timeoutMs) || config.timeoutMs < 1 || config.timeoutMs > 5000
      || !Number.isSafeInteger(config.maxConcurrent) || config.maxConcurrent < 1 || config.maxConcurrent > 16) throw new TypeError('invalid config');
  let base;
  try {
    if (/\\s|\\\\/.test(config.baseUrl)) throw new TypeError('invalid config');
    base = new URL(config.baseUrl);
    if (base.protocol !== 'https:' || config.baseUrl !== base.origin && config.baseUrl !== `${base.origin}/`) throw new TypeError('invalid config');
    tls.createSecureContext({ ca: config.tls.ca, cert: config.tls.cert, key: config.tls.key, minVersion: 'TLSv1.2' });
  } catch { throw new TypeError('invalid config'); }
  try {
    const registration = structuredClone(config.registration);
    if (!validRegistration(registration)) throw new TypeError('invalid config');
    return frozenCopy({ baseUrl: base.href, hostname: base.hostname, port: base.port, registration, tls: structuredClone(config.tls), timeoutMs: config.timeoutMs, maxConcurrent: config.maxConcurrent });
  } catch { throw new TypeError('invalid config'); }
}

function requestCopy(input, method) {
  if (!exact(input,new Set(INPUTS[method])) || typeof input.flow_id !== 'string' || !UUID.test(input.flow_id)) throw invalid();
  if (method === 'open' && (!isHandle(input.channel_id) || !isTime(input.expires_at_ms))) throw invalid();
  if (method === 'pair' && !isHandle(input.return_handle)) throw invalid();
  if (['reservation','confirmation','outcome'].includes(method) && !isCompact(input[INPUTS[method][1]])) throw invalid();
  const body = Buffer.from(JSON.stringify(input),'utf8');
  if (body.length > MAX_BODY) throw invalid();
  return Object.freeze({body, flowId: input.flow_id});
}
function validResult(value, method, flowId, registration) {
  if (!exact(value,new Set(['flow_id','state','expires_at_ms','context','scoped_subject','offer_handle','material']))
      || value.flow_id !== flowId || !isTime(value.expires_at_ms) || !validRegistration(value.context)
      || !CONTEXT.every(key => value.context[key] === registration[key]) || typeof value.state !== 'string'
      || !(Object.hasOwn(PHASES,value.state) || value.state === 'expired') || !exact(value.material,new Set(MATERIAL))) return false;
  let count=0; let gap=false;
  for (const key of MATERIAL) {
    const item=value.material[key];
    if (item === null) {gap=true;continue;}
    if (gap) return false;
    count++;
    if (key === 'statement') {
      if (typeof item !== 'string' || Buffer.byteLength(item,'utf8') > 16384) return false;
      try { if (!plain(parseStrictJson(Buffer.from(item,'utf8'),16384))) return false; } catch { return false; }
    } else if (!isCompact(item)) return false;
  }
  if (value.state === 'expired' ? count >= 5 : count !== PHASES[value.state]) return false;
  if (value.offer_handle !== null && (method !== 'open' || value.state !== 'offered' || !isHandle(value.offer_handle))) return false;
  if (['offered','claimed'].includes(value.state)) return value.scoped_subject === null;
  if (value.state === 'expired' && value.scoped_subject === null) return count === 0;
  return typeof value.scoped_subject === 'string' && ID.test(value.scoped_subject);
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
function resultFor(response, bytes, method, flowId, registration) {
  if (!validHeaders(response) || Number(oneHeader(response.rawHeaders, 'content-length')) !== bytes.length) throw unavailable();
  let body;
  try {
    body = parseStrictJson(bytes, MAX_RESPONSE);
    // This closed envelope has exactly one numeric field: expires_at_ms.
    // Validate its wire token before JSON.parse's IEEE-754 rounding can turn
    // a fractional or out-of-range number into a permitted integer. Strings
    // (including the opaque original account statement) are not inspected.
    const text = bytes.toString('utf8');
    visit(text, { onLiteralValue(value, offset, length) {
      if (typeof value === 'number' && !/^(0|[1-9][0-9]*)(?![\s\S])/.test(text.slice(offset, offset + length))) throw unavailable();
    } });
  } catch { throw unavailable(); }
  if (response.statusCode === 200) {
    if (!validResult(body,method,flowId,registration)) throw unavailable();
    return frozenCopy(body);
  }
  const permitted = SAFE_ERRORS.get(response.statusCode);
  if (!permitted || !exact(body, new Set(['error'])) || !exact(body.error, new Set(['code'])) || typeof body.error.code !== 'string' || !permitted.has(body.error.code)) throw unavailable();
  throw new OwnerConnectorTransportError(body.error.code);
}

export function createOwnerConnectorClient(config) {
  const saved = configCopy(config);
  let agent;
  try { agent = new https.Agent({ keepAlive: true, maxSockets: saved.maxConcurrent, maxFreeSockets: 0, maxCachedSessions: 0, ca: saved.tls.ca, cert: saved.tls.cert, key: saved.tls.key, minVersion: 'TLSv1.2', rejectUnauthorized: true }); } catch { throw new TypeError('invalid config'); }
  let closed = false;
  let active = 0;
  const operations = new Set();

  function call(method, input) {
    let request;
    try { request = requestCopy(input, method); } catch (error) { return Promise.reject(error instanceof OwnerConnectorTransportError ? error : invalid()); }
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
        if (error) reject(error instanceof OwnerConnectorTransportError ? error : unavailable()); else resolve(value);
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
        const req = https.request({ protocol: 'https:', hostname: saved.hostname, port: saved.port || undefined, servername: saved.hostname, path: METHODS[method], method: 'POST', agent, minVersion: 'TLSv1.2', rejectUnauthorized: true, headers: { Host: saved.port ? `${saved.hostname}:${saved.port}` : saved.hostname, 'Content-Type': 'application/json', 'Content-Length': String(request.body.length), Accept: 'application/json', 'Cache-Control': 'no-store' } }, (res) => {
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
            try { finish(null, resultFor(res, Buffer.concat(chunks), method, request.flowId, saved.registration)); } catch (error) { finish(error); }
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
    open(input) { return call('open',input); },
    pair(input) { return call('pair',input); },
    reservation(input) { return call('reservation',input); },
    confirmation(input) { return call('confirmation',input); },
    outcome(input) { return call('outcome',input); },
    read(input) { return call('read',input); },
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
