import { createHash, timingSafeEqual } from 'node:crypto';

const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const MAX_TIME = 8_640_000_000_000_000;
const SANDBOX_HASH = 'sha256:dc6f6409a47da2a97ea7b4ace313985d7fcd4c6b8459a59ea06b014de304a175';
const ENERGY_HASH = 'sha256:e1c5106dc710ce0ba3d846f3cb376358eb858c35adfbac906f0ff58f3a6451fa';
const ENERGY_FIELDS = Object.freeze([
  'network', 'resource', 'amount', 'duration_sec', 'recipient', 'execution_provider',
  'quote_id', 'quote_expires_at_ms', 'resource_cost_sun', 'platform_fee_sun',
  'activation_fee_cap_sun', 'network_fee_cap_sun', 'max_total_debit_sun',
]);
const DURATIONS = new Set([120, 300, 600, 900, 1_800, 3_600, 10_800, 21_600, 86_400]);
const REGISTRATION_FIELDS = new Set([
  'issuer', 'audience', 'environment', 'tenant_id', 'resource_id', 'quota_scope_id',
  'operation_namespace', 'resource_profile_version', 'resource_profile_hash', 'policy_version',
  'account_required_actions',
]);
const PARTY = /^[A-Za-z0-9:/._-]{1,256}(?![\s\S])/;
const ID = /^[A-Za-z0-9._:-]{1,128}(?![\s\S])/;
const UUID4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\s\S])/;
const SUN = /^(?:0|[1-9][0-9]*)(?![\s\S])/;
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_INDEX = new Map([...BASE58].map((value, index) => [value, BigInt(index)]));
const ACTION_NAME = /^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*(?![\s\S])/;
const HASH = /^sha256:[0-9a-f]{64}(?![\s\S])/;
const DESCRIPTOR_FIELDS = new Set(['profile', 'actions', 'account_required_actions']);
const SERVICE_PROFILES = new WeakSet();

export const GENERIC_SERVICE_PROFILE = 'atum.service-actions.v1-draft.1';

export const MERX_ENERGY_DESCRIPTOR_JSON = '{"action":{"name":"energy.purchase","parameters":{"activation_fee_cap_sun":{"canonical":"unsigned_decimal_string","maximum":"9007199254740991","minimum":"0"},"amount":{"maximum":1000000000,"minimum":65000,"type":"safe_integer"},"duration_sec":{"enum":[120,300,600,900,1800,3600,10800,21600,86400]},"execution_provider":{"const":"powersun-merx"},"max_total_debit_sun":{"canonical":"unsigned_decimal_string","maximum":"9007199254740991","minimum":"1"},"network":{"const":"tron-mainnet"},"network_fee_cap_sun":{"canonical":"unsigned_decimal_string","const":"0","maximum":"9007199254740991","minimum":"0"},"platform_fee_sun":{"canonical":"unsigned_decimal_string","const":"0","maximum":"9007199254740991","minimum":"0"},"quote_expires_at_ms":{"maximum":8640000000000000,"minimum":1,"type":"safe_integer"},"quote_id":{"canonical":"lowercase","format":"uuidv4"},"recipient":{"format":"tron_base58check"},"resource":{"const":"ENERGY"},"resource_cost_sun":{"canonical":"unsigned_decimal_string","maximum":"9007199254740991","minimum":"1"}},"required":["network","resource","amount","duration_sec","recipient","execution_provider","quote_id","quote_expires_at_ms","resource_cost_sun","platform_fee_sun","activation_fee_cap_sun","network_fee_cap_sun","max_total_debit_sun"]},"canonical_json":{"encoding":"utf-8","integer":"safe_integer","key_order":"lexicographic","whitespace":"none"},"environment":"production","fees":{"max_total_debit_sun":"resource_cost_sun+platform_fee_sun+activation_fee_cap_sun+network_fee_cap_sun","network_fee_cap_sun":"0","platform_fee_sun":"0"},"permission":{"exact_action":true,"grant_expiry":"<=quote_expires_at_ms","grant_limit":1,"single_permission":true},"profile":"merx.energy-purchase.v1-draft.1"}';

const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype;
const invalid = () => { throw new TypeError('invalid resource profile value'); };
const exact = (value, fields) => {
  if (!plain(value) || Object.keys(value).length !== fields.size || Object.keys(value).some(key => !fields.has(key))) invalid();
};
const integer = (value, minimum, maximum = MAX_SAFE) => {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || Object.is(value, -0) || value < minimum || value > maximum) invalid();
  return value;
};
const freeze = value => {
  if (Array.isArray(value)) value.forEach(freeze);
  else if (plain(value)) Object.values(value).forEach(freeze);
  return value && typeof value === 'object' ? Object.freeze(value) : value;
};
const copy = value => freeze(structuredClone(value));

function scalarString(value) {
  if (typeof value !== 'string') invalid();
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const low = value.charCodeAt(index + 1);
      if (!(low >= 0xdc00 && low <= 0xdfff)) invalid();
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) invalid();
  }
  return value;
}

function canonicalValue(value, depth = 0) {
  if (depth > 8) invalid();
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') return scalarString(value);
  if (typeof value === 'number') return integer(value, -MAX_SAFE, MAX_SAFE);
  if (Array.isArray(value)) {
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1 || keys.some((key) => key !== 'length'
        && (typeof key !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length))
        || Array.from({ length: value.length }, (_, index) => index).some(index => !Object.hasOwn(value, index))) invalid();
    return value.map(item => canonicalValue(item, depth + 1));
  }
  if (!plain(value)) invalid();
  const result = {};
  for (const key of Object.keys(value).sort()) {
    if (!/^[\x20-\x7e]{1,128}(?![\s\S])/.test(key) || ['__proto__', 'prototype', 'constructor'].includes(key)) invalid();
    result[key] = canonicalValue(value[key], depth + 1);
  }
  if (Reflect.ownKeys(value).length !== Object.keys(value).length) invalid();
  return result;
}

function canonicalJson(value, maximum = Infinity) {
  const normalized = canonicalValue(value);
  const serialize = item => {
    if (item === null || typeof item !== 'object') return JSON.stringify(item);
    if (Array.isArray(item)) return `[${item.map(serialize).join(',')}]`;
    return `{${Object.keys(item).sort().map(key => `${JSON.stringify(key)}:${serialize(item[key])}`).join(',')}}`;
  };
  const text = serialize(normalized);
  if (Buffer.byteLength(text, 'utf8') > maximum) invalid();
  return text;
}

function descriptorValue(value) {
  exact(value, DESCRIPTOR_FIELDS);
  if (value.profile !== GENERIC_SERVICE_PROFILE || !Array.isArray(value.actions)
      || value.actions.length < 1 || value.actions.length > 64
      || !Array.isArray(value.account_required_actions)) invalid();
  const actions = value.actions.map(action => {
    if (typeof action !== 'string' || action.length > 128 || !ACTION_NAME.test(action)) invalid();
    return action;
  });
  const required = value.account_required_actions.map(action => {
    if (typeof action !== 'string' || action.length > 128 || !ACTION_NAME.test(action)) invalid();
    return action;
  });
  if (new Set(actions).size !== actions.length || new Set(required).size !== required.length
      || actions.some((action, index) => index > 0 && actions[index - 1] >= action)
      || required.some((action, index) => index > 0 && required[index - 1] >= action)
      || required.some(action => !actions.includes(action))) invalid();
  return freeze({ profile: GENERIC_SERVICE_PROFILE, actions: freeze(actions), account_required_actions: freeze(required) });
}

export function canonicalServiceDescriptor(value) {
  const descriptor = descriptorValue(value);
  return canonicalJson({ account_required_actions: descriptor.account_required_actions,
    actions: descriptor.actions, profile: descriptor.profile });
}

export function hashServiceDescriptor(value) {
  return `sha256:${createHash('sha256').update(canonicalServiceDescriptor(value), 'utf8').digest('hex')}`;
}

function serviceProfile(value) {
  const descriptor = descriptorValue(value);
  const profile = freeze({ kind: 'service', profile: descriptor.profile, hash: hashServiceDescriptor(descriptor),
    actions: descriptor.actions, account_required_actions: descriptor.account_required_actions, descriptor });
  SERVICE_PROFILES.add(profile);
  return profile;
}

export function createServiceProfile(value) {
  return serviceProfile(value);
}

export function canonicalServiceAction(value, descriptor) {
  const action = normalizeProfileAction(value, serviceProfile(descriptor));
  return canonicalJson({ action: action.action, parameters: action.parameters });
}

const energyDescriptor = JSON.parse(MERX_ENERGY_DESCRIPTOR_JSON);
if (`sha256:${createHash('sha256').update(MERX_ENERGY_DESCRIPTOR_JSON, 'utf8').digest('hex')}` !== ENERGY_HASH) {
  throw new Error('Energy descriptor hash mismatch');
}

function registeredProfile(descriptor, actions) {
  Object.defineProperty(descriptor, 'actions', {
    value: Object.freeze(actions), enumerable: false, writable: false, configurable: false,
  });
  return freeze(descriptor);
}

export const MERX_SANDBOX_V1 = registeredProfile({
  profile: 'v1-draft.1', environment: 'sandbox', hash: SANDBOX_HASH,
}, ['prices.read', 'order.preview', 'sandbox.execute']);
export const MERX_ENERGY_V1 = registeredProfile({
  ...energyDescriptor, hash: ENERGY_HASH,
}, ['prices.read', 'order.preview', 'energy.purchase']);

function profileFor(version, hash, environment, descriptor) {
  if (descriptor !== undefined && version !== GENERIC_SERVICE_PROFILE) invalid();
  if (version === MERX_SANDBOX_V1.profile && hash === MERX_SANDBOX_V1.hash && environment === MERX_SANDBOX_V1.environment) return MERX_SANDBOX_V1;
  if (version === MERX_ENERGY_V1.profile && hash === MERX_ENERGY_V1.hash && environment === MERX_ENERGY_V1.environment) return MERX_ENERGY_V1;
  if (version === GENERIC_SERVICE_PROFILE && descriptor !== undefined && ['sandbox', 'production'].includes(environment)) {
    const profile = serviceProfile(descriptor);
    if (hash === profile.hash) return profile;
  }
  invalid();
}

export function selectResourceProfile(value, descriptor) {
  if (!plain(value)) invalid();
  return profileFor(value.resource_profile_version, value.resource_profile_hash, value.environment, descriptor);
}

export function validateResourceRegistration(value, descriptor) {
  exact(value, REGISTRATION_FIELDS);
  if (typeof value.issuer !== 'string' || !PARTY.test(value.issuer)
      || typeof value.audience !== 'string' || !PARTY.test(value.audience)) invalid();
  for (const field of ['tenant_id', 'resource_id', 'quota_scope_id', 'operation_namespace', 'policy_version']) {
    if (typeof value[field] !== 'string' || !ID.test(value[field])) invalid();
  }
  if (typeof value.resource_profile_hash !== 'string' || !HASH.test(value.resource_profile_hash)) invalid();
  const profile = profileFor(value.resource_profile_version, value.resource_profile_hash, value.environment, descriptor);
  if (!Array.isArray(value.account_required_actions)
      || value.account_required_actions.some(action => typeof action !== 'string' || !profile.actions.includes(action))
      || new Set(value.account_required_actions).size !== value.account_required_actions.length
      || (profile === MERX_ENERGY_V1 && !value.account_required_actions.includes('energy.purchase'))
      || (SERVICE_PROFILES.has(profile) && (value.account_required_actions.length !== profile.account_required_actions.length
        || value.account_required_actions.some((action, index) => action !== profile.account_required_actions[index])))) invalid();
  return freeze({ registration: copy(value), profile });
}

function decodeBase58(value) {
  if (typeof value !== 'string' || value.length !== 34) invalid();
  let number = 0n;
  for (const character of value) {
    const digit = BASE58_INDEX.get(character);
    if (digit === undefined) invalid();
    number = number * 58n + digit;
  }
  let hex = number.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  let decoded = number === 0n ? Buffer.alloc(0) : Buffer.from(hex, 'hex');
  let zeroes = 0;
  while (value[zeroes] === '1') zeroes += 1;
  if (zeroes) decoded = Buffer.concat([Buffer.alloc(zeroes), decoded]);
  return decoded;
}

function tronAddress(value) {
  const decoded = decodeBase58(value);
  if (decoded.length !== 25 || decoded[0] !== 0x41) invalid();
  const payload = decoded.subarray(0, 21);
  const expected = createHash('sha256').update(createHash('sha256').update(payload).digest()).digest().subarray(0, 4);
  if (!timingSafeEqual(decoded.subarray(21), expected)) invalid();
  return value;
}

function sun(value) {
  if (typeof value !== 'string' || !SUN.test(value)) invalid();
  const parsed = BigInt(value);
  if (parsed > BigInt(MAX_SAFE)) invalid();
  return parsed;
}

function normalizeEnergy(value) {
  exact(value, new Set(['action', 'parameters']));
  if (value.action !== 'energy.purchase') invalid();
  exact(value.parameters, new Set(ENERGY_FIELDS));
  const source = value.parameters;
  if (source.network !== 'tron-mainnet' || source.resource !== 'ENERGY'
      || source.execution_provider !== 'powersun-merx' || !DURATIONS.has(source.duration_sec)
      || typeof source.quote_id !== 'string' || !UUID4.test(source.quote_id)) invalid();
  integer(source.amount, 65_000, 1_000_000_000);
  integer(source.quote_expires_at_ms, 1, MAX_TIME);
  tronAddress(source.recipient);
  const resource = sun(source.resource_cost_sun);
  const platform = sun(source.platform_fee_sun);
  const activation = sun(source.activation_fee_cap_sun);
  const network = sun(source.network_fee_cap_sun);
  const total = sun(source.max_total_debit_sun);
  if (resource < 1n || platform !== 0n || network !== 0n || total < 1n
      || resource + platform + activation + network > BigInt(MAX_SAFE)
      || total !== resource + platform + activation + network) invalid();
  return copy({ action: value.action, parameters: Object.fromEntries(ENERGY_FIELDS.map(field => [field, source[field]])) });
}

export function normalizeProfileAction(value, profile) {
  if (SERVICE_PROFILES.has(profile)) {
    exact(value, new Set(['action', 'parameters']));
    if (typeof value.action !== 'string' || !profile.actions.includes(value.action) || !plain(value.parameters)) invalid();
    const parameters = canonicalValue(value.parameters);
    canonicalJson(parameters, 16_384);
    return copy({ action: value.action, parameters });
  }
  if (profile !== MERX_SANDBOX_V1 && profile !== MERX_ENERGY_V1) invalid();
  exact(value, new Set(['action', 'parameters']));
  if (!profile.actions.includes(value.action) || !plain(value.parameters)) invalid();
  if (value.action === 'energy.purchase') return normalizeEnergy(value);
  if (value.action === 'prices.read') {
    if (Object.keys(value.parameters).length) invalid();
    return freeze({ action: 'prices.read', parameters: freeze({}) });
  }
  if (value.action === 'sandbox.execute' && profile !== MERX_SANDBOX_V1) invalid();
  exact(value.parameters, new Set(Object.hasOwn(value.parameters, 'max_price_sun')
    ? ['resource', 'amount', 'duration', 'max_price_sun'] : ['resource', 'amount', 'duration']));
  if (!['ENERGY', 'BANDWIDTH'].includes(value.parameters.resource)) invalid();
  const parameters = { resource: value.parameters.resource,
    amount: integer(value.parameters.amount, 1, 1_000_000_000),
    duration: integer(value.parameters.duration, 1, 2_592_000) };
  if (Object.hasOwn(value.parameters, 'max_price_sun')) parameters.max_price_sun = integer(value.parameters.max_price_sun, 1, 1_000_000_000_000);
  return copy({ action: value.action, parameters });
}

export function normalizeProfilePermission(value, profile) {
  if (SERVICE_PROFILES.has(profile)) {
    exact(value, new Set(['action']));
    if (typeof value.action !== 'string' || !profile.actions.includes(value.action)) invalid();
    return freeze({ action: value.action });
  }
  if (profile !== MERX_SANDBOX_V1 && profile !== MERX_ENERGY_V1) invalid();
  if (!plain(value) || typeof value.action !== 'string' || !profile.actions.includes(value.action)) invalid();
  if (value.action === 'energy.purchase') return normalizeEnergy(value);
  if (value.action === 'prices.read') {
    exact(value, new Set(['action']));
    return freeze({ action: value.action });
  }
  exact(value, new Set(['action', 'max_amount', 'max_duration', 'max_price_sun']));
  if (value.action === 'sandbox.execute' && profile !== MERX_SANDBOX_V1) invalid();
  return freeze({ action: value.action, max_amount: integer(value.max_amount, 1, 1_000_000_000),
    max_duration: integer(value.max_duration, 1, 2_592_000),
    max_price_sun: value.max_price_sun === null ? null : integer(value.max_price_sun, 1, 1_000_000_000_000) });
}

export function normalizeProfileGrant(value, profile) {
  if (profile !== MERX_SANDBOX_V1 && profile !== MERX_ENERGY_V1 && !SERVICE_PROFILES.has(profile)) invalid();
  exact(value, new Set(['permissions', 'grant_limit', 'grant_expires_at_ms']));
  integer(value.grant_limit, 0, 1_000_000_000);
  integer(value.grant_expires_at_ms, 0, MAX_TIME);
  const maximumPermissions = SERVICE_PROFILES.has(profile) ? profile.actions.length : 3;
  if (!Array.isArray(value.permissions) || !value.permissions.length || value.permissions.length > maximumPermissions) invalid();
  const permissions = value.permissions.map(permission => normalizeProfilePermission(permission, profile))
    .sort((left, right) => left.action < right.action ? -1 : left.action > right.action ? 1 : 0);
  if (new Set(permissions.map(permission => permission.action)).size !== permissions.length) invalid();
  const energy = permissions.find(permission => permission.action === 'energy.purchase');
  if (energy && (permissions.length !== 1 || value.grant_limit !== 1
      || value.grant_expires_at_ms > energy.parameters.quote_expires_at_ms)) invalid();
  return freeze({ permissions: freeze(permissions), grant_limit: value.grant_limit,
    grant_expires_at_ms: value.grant_expires_at_ms });
}
