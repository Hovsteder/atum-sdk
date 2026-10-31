import { createHash } from 'node:crypto';
import { visit } from 'jsonc-parser';
import {
  MERX_ENERGY_V1,
  MERX_SANDBOX_V1,
  GENERIC_SERVICE_PROFILE,
  canonicalServiceAction,
  createServiceProfile,
  normalizeProfileAction,
  selectResourceProfile,
  validateResourceRegistration,
} from './resource-profiles.mjs';

const MAX_SAFE_INT = Number.MAX_SAFE_INTEGER;
const PROTOCOL_VERSION = '0.1.0-draft.2';
const ID_RE = /^[A-Za-z0-9._:-]{1,128}(?![\s\S])/;
const PARTY_RE = /^[A-Za-z0-9:/._-]{1,256}(?![\s\S])/;
const HASH_RE = /^sha256:[0-9a-f]{64}(?![\s\S])/;
const BASE64URL_43_RE = /^[A-Za-z0-9_-]{43}(?![\s\S])/;
const KNOWN_ACTIONS = new Set(['prices.read', 'order.preview', 'sandbox.execute', 'energy.purchase']);
const SERVICE_ACTION_RE = /^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*(?![\s\S])/;
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

function validateAction(request, descriptor) {
  try {
    if (descriptor !== undefined) return normalizeProfileAction(request, createServiceProfile(descriptor));
    return normalizeProfileAction(request, request?.action === 'energy.purchase' ? MERX_ENERGY_V1 : MERX_SANDBOX_V1);
  } catch { invalid(); }
}

function validateContext(context, descriptor) {
  exactObject(context, CONTEXT_FIELDS);
  if (context.protocol_version !== PROTOCOL_VERSION) invalid();
  let profile;
  const generic = context.resource_profile_version === GENERIC_SERVICE_PROFILE;
  try {
    if (generic && descriptor === undefined) {
      if (!['sandbox', 'production'].includes(context.environment)) invalid();
      string(context.resource_profile_hash, HASH_RE);
    } else profile = selectResourceProfile(context, descriptor);
  } catch { invalid(); }
  string(context.issuer, PARTY_RE);
  string(context.audience, PARTY_RE);
  for (const field of ['tenant_id', 'resource_id', 'quota_scope_id', 'operation_namespace', 'scoped_subject', 'operation_id', 'grant_id', 'policy_version']) {
    string(context[field], ID_RE);
  }
  const grantVersion = integral(context.grant_version, 1);
  base64url32(context.agent_key_thumbprint);
  string(context.consent_hash, HASH_RE);
  string(context.action_hash, HASH_RE);
  if (typeof context.action !== 'string'
      || (generic ? !SERVICE_ACTION_RE.test(context.action) || (profile && !profile.actions.includes(context.action))
        : !KNOWN_ACTIONS.has(context.action) || !profile.actions.includes(context.action))) invalid();
  let accountVersion;
  if (context.account_binding_id === null) {
    if (context.account_binding_version !== null) invalid();
    if (context.action === 'energy.purchase') invalid();
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

export function canonicalAction(request, descriptor) {
  const action = validateAction(request, descriptor);
  if (descriptor !== undefined) return canonicalServiceAction(action, descriptor);
  if (action.action === 'prices.read') return '{"action":"prices.read","parameters":{}}';
  if (action.action === 'energy.purchase') return JSON.stringify({ action: action.action, parameters: Object.fromEntries(Object.keys(action.parameters).sort().map(key => [key, action.parameters[key]])) });
  const parameters = {};
  for (const key of ['amount', 'duration', 'max_price_sun', 'resource']) {
    if (Object.hasOwn(action.parameters, key)) parameters[key] = action.parameters[key];
  }
  return JSON.stringify({ action: action.action, parameters });
}

export function actionHash(request, descriptor) {
  return hash(descriptor === undefined ? 'merx.atum.intent.v1\n' : 'atum.service.action.v1\n', canonicalAction(request, descriptor));
}

export function canonicalContext(context, descriptor) {
  const normalized = validateContext(context, descriptor);
  const ordered = {};
  for (const key of Object.keys(normalized).sort()) ordered[key] = normalized[key];
  return JSON.stringify(ordered);
}

export function intentHash(context, descriptor) {
  return hash('atum.admission.context.v1\n', canonicalContext(context, descriptor));
}

export function validateBoundIntent(context, request, registration, descriptor) {
  const normalized = validateContext(context, descriptor);
  let selected;
  try { selected = validateResourceRegistration(registration, descriptor); } catch { invalid(); }
  const action = (() => { try { return normalizeProfileAction(request, selected.profile); } catch { invalid(); } })();
  for (const field of REGISTRATION_FIELDS) {
    if (field !== 'account_required_actions' && registration[field] !== normalized[field]) invalid();
  }
  const required = selected.registration.account_required_actions;
  if (action.action !== normalized.action || actionHash(request, descriptor) !== normalized.action_hash) invalid();
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
