import { createHash } from 'node:crypto';
import { visit } from 'jsonc-parser';

const MAX_SAFE_INT = Number.MAX_SAFE_INTEGER;
const PROFILE_HASH = 'sha256:dc6f6409a47da2a97ea7b4ace313985d7fcd4c6b8459a59ea06b014de304a175';
const PROTOCOL_VERSION = '0.1.0-draft.2';
const ID_RE = /^[A-Za-z0-9._:-]{1,128}(?![\s\S])/;
const PARTY_RE = /^[A-Za-z0-9:/._-]{1,256}(?![\s\S])/;
const HASH_RE = /^sha256:[0-9a-f]{64}(?![\s\S])/;
const BASE64URL_43_RE = /^[A-Za-z0-9_-]{43}(?![\s\S])/;
const KNOWN_ACTIONS = new Set(['prices.read', 'order.preview', 'sandbox.execute']);
const CONTEXT_FIELDS = new Set([
  'protocol_version', 'resource_profile_version', 'resource_profile_hash', 'issuer', 'audience',
  'environment', 'tenant_id', 'resource_id', 'quota_scope_id', 'operation_namespace',
  'scoped_subject', 'operation_id', 'grant_id', 'grant_version', 'policy_version',
  'agent_key_thumbprint', 'consent_hash', 'action_hash', 'account_binding_id',
  'account_binding_version', 'action',
]);
const REGISTRATION_FIELDS = new Set([
  'issuer', 'audience', 'environment', 'tenant_id', 'resource_id', 'quota_scope_id',
  'operation_namespace', 'resource_profile_version', 'resource_profile_hash', 'policy_version',
  'account_required_actions',
]);
const PROTOTYPE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const utf8Decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const utf8Encoder = new TextEncoder();

function invalid() {
  throw new TypeError('invalid input');
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exactObject(value, fields) {
  if (!isPlainObject(value)) invalid();
  const keys = Object.keys(value);
  if (keys.length !== fields.size || keys.some((key) => !fields.has(key))) invalid();
}

function string(value, pattern) {
  if (typeof value !== 'string' || !pattern.test(value)) invalid();
}

function integral(value, lower, upper = MAX_SAFE_INT) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < lower || value > upper) invalid();
  return value;
}

function base64url32(value) {
  string(value, BASE64URL_43_RE);
  let decoded;
  try {
    decoded = Buffer.from(`${value}=`, 'base64url');
  } catch {
    invalid();
  }
  if (decoded.length !== 32 || decoded.toString('base64url') !== value) invalid();
}

function hash(domain, canonical) {
  return `sha256:${createHash('sha256').update(domain, 'ascii').update(canonical, 'utf8').digest('hex')}`;
}

function validateAction(request) {
  exactObject(request, new Set(['action', 'parameters']));
  if (typeof request.action !== 'string' || !KNOWN_ACTIONS.has(request.action)) invalid();
  if (!isPlainObject(request.parameters)) invalid();
  if (request.action === 'prices.read') {
    if (Object.keys(request.parameters).length !== 0) invalid();
    return { action: request.action, parameters: {} };
  }
  const allowed = new Set(['resource', 'amount', 'duration', 'max_price_sun']);
  const keys = Object.keys(request.parameters);
  if (!['resource', 'amount', 'duration'].every((key) => Object.hasOwn(request.parameters, key))
      || keys.some((key) => !allowed.has(key))) invalid();
  if (request.parameters.resource !== 'ENERGY' && request.parameters.resource !== 'BANDWIDTH') invalid();
  const parameters = {
    resource: request.parameters.resource,
    amount: integral(request.parameters.amount, 1, 1_000_000_000),
    duration: integral(request.parameters.duration, 1, 2_592_000),
  };
  if (Object.hasOwn(request.parameters, 'max_price_sun')) {
    parameters.max_price_sun = integral(request.parameters.max_price_sun, 1, 1_000_000_000_000);
  }
  return { action: request.action, parameters };
}

function validateContext(context) {
  exactObject(context, CONTEXT_FIELDS);
  if (context.protocol_version !== PROTOCOL_VERSION
      || context.resource_profile_version !== 'v1-draft.1'
      || context.resource_profile_hash !== PROFILE_HASH
      || context.environment !== 'sandbox') invalid();
  string(context.issuer, PARTY_RE);
  string(context.audience, PARTY_RE);
  for (const field of ['tenant_id', 'resource_id', 'quota_scope_id', 'operation_namespace', 'scoped_subject', 'operation_id', 'grant_id', 'policy_version']) {
    string(context[field], ID_RE);
  }
  const grantVersion = integral(context.grant_version, 1);
  base64url32(context.agent_key_thumbprint);
  string(context.consent_hash, HASH_RE);
  string(context.action_hash, HASH_RE);
  if (typeof context.action !== 'string' || !KNOWN_ACTIONS.has(context.action)) invalid();
  let accountVersion;
  if (context.account_binding_id === null) {
    if (context.account_binding_version !== null) invalid();
    accountVersion = null;
  } else {
    string(context.account_binding_id, ID_RE);
    accountVersion = integral(context.account_binding_version, 1);
  }
  return { ...context, grant_version: grantVersion, account_binding_version: accountVersion };
}

function scanStrictJson(text) {
  const objects = [];
  let depth = 0;
  visit(text, {
    onObjectBegin() {
      depth += 1;
      if (depth > 12) invalid();
      objects.push(new Set());
    },
    onObjectProperty(key) {
      const keys = objects.at(-1);
      if (!keys || keys.has(key) || PROTOTYPE_KEYS.has(key)) invalid();
      else keys.add(key);
    },
    onObjectEnd() {
      objects.pop();
      depth -= 1;
    },
    onArrayBegin() {
      depth += 1;
      if (depth > 12) invalid();
    },
    onArrayEnd() {
      depth -= 1;
    },
    onComment() { invalid(); },
    onError() { invalid(); },
  }, { allowTrailingComma: false, disallowComments: true, allowEmptyContent: false });
}

/** Parse a bounded, duplicate-safe JSON object at a wire boundary. */
export function parseStrictJson(input, maxBytes = 32768) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) invalid();
  let text;
  if (typeof input === 'string') {
    text = input;
    if (text.length > maxBytes) invalid();
    if (utf8Encoder.encode(text).byteLength > maxBytes) invalid();
  } else if (input instanceof Uint8Array) {
    if (input.byteLength > maxBytes) invalid();
    try {
      text = utf8Decoder.decode(input);
    } catch {
      invalid();
    }
  } else {
    invalid();
  }

  scanStrictJson(text);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    invalid();
  }
  if (!isPlainObject(parsed)) invalid();
  const stack = [parsed];
  while (stack.length) {
    const value = stack.pop();
    if (typeof value === 'number' && !Number.isFinite(value)) invalid();
    if (value !== null && typeof value === 'object') stack.push(...Object.values(value));
  }
  return parsed;
}

export function canonicalAction(request) {
  const action = validateAction(request);
  if (action.action === 'prices.read') return '{"action":"prices.read","parameters":{}}';
  const parameters = {};
  for (const key of ['amount', 'duration', 'max_price_sun', 'resource']) {
    if (Object.hasOwn(action.parameters, key)) parameters[key] = action.parameters[key];
  }
  return JSON.stringify({ action: action.action, parameters });
}

export function actionHash(request) {
  return hash('merx.atum.intent.v1\n', canonicalAction(request));
}

export function canonicalContext(context) {
  const normalized = validateContext(context);
  const ordered = {};
  for (const key of Object.keys(normalized).sort()) ordered[key] = normalized[key];
  return JSON.stringify(ordered);
}

export function intentHash(context) {
  return hash('atum.admission.context.v1\n', canonicalContext(context));
}

export function validateBoundIntent(context, request, registration) {
  const normalized = validateContext(context);
  const action = validateAction(request);
  exactObject(registration, REGISTRATION_FIELDS);
  for (const field of REGISTRATION_FIELDS) {
    if (field !== 'account_required_actions' && registration[field] !== normalized[field]) invalid();
  }
  const required = registration.account_required_actions;
  if (!Array.isArray(required) || required.some((item) => typeof item !== 'string' || !KNOWN_ACTIONS.has(item))
      || new Set(required).size !== required.length) invalid();
  if (action.action !== normalized.action || actionHash(request) !== normalized.action_hash) invalid();
  if (required.includes(normalized.action) && normalized.account_binding_id === null) invalid();
}

export function operationKey(context) {
  const normalized = validateContext(context);
  return ['issuer', 'environment', 'tenant_id', 'resource_id', 'quota_scope_id', 'operation_namespace', 'scoped_subject', 'operation_id']
    .map((field) => normalized[field]);
}

export function quotaKey(context) {
  const normalized = validateContext(context);
  return ['issuer', 'environment', 'tenant_id', 'resource_id', 'quota_scope_id', 'scoped_subject']
    .map((field) => normalized[field]);
}
