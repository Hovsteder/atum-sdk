import { configSnapshot, safeTime } from './validation.mjs';

const FACT = ['nonce_issue_only', 'issuer', 'audience', 'endpoint_url', 'agent_key_thumbprint', 'proof_jti',
  'intent_hash', 'token_expires_at_ms', 'proof_iat_ms', 'replay_expires_at_ms', 'verified_now_ms', 'verified_upper_bound_ms'];
const invalid = () => { throw new TypeError('invalid input'); };

function record(value, fields) {
  let descriptors;
  try {
    if (value === null || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) invalid();
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch { invalid(); }
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length !== fields.length || keys.some(key => typeof key !== 'string' || !fields.includes(key))) invalid();
  const copy = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) invalid();
    copy[key] = descriptor.value;
  }
  return copy;
}

export function challengeConfig(value) {
  try {
    const config = record(value, ['pool', 'clock', 'binding', 'maxActiveNoncesPerKey']);
    const bound = record(config.binding, ['issuer', 'audience', 'endpoint_url']);
    const binding = configSnapshot({ pool: config.pool, clock: config.clock, binding: bound });
    if (!Number.isSafeInteger(config.maxActiveNoncesPerKey) || config.maxActiveNoncesPerKey < 1 || config.maxActiveNoncesPerKey > 64) invalid();
    return Object.freeze({ binding, clock: config.clock, connect: config.pool.connect.bind(config.pool), cap: config.maxActiveNoncesPerKey });
  } catch { throw new TypeError('invalid config'); }
}

export function challengeFact(value, binding) {
  const fact = record(value, FACT);
  if (fact.nonce_issue_only !== true || ['issuer', 'audience', 'endpoint_url'].some(key => fact[key] !== binding[key])
      || typeof fact.agent_key_thumbprint !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(fact.agent_key_thumbprint)
      || Buffer.from(fact.agent_key_thumbprint, 'base64url').toString('base64url') !== fact.agent_key_thumbprint
      || typeof fact.proof_jti !== 'string' || fact.proof_jti.length < 16 || fact.proof_jti.length > 128 || /[^A-Za-z0-9_-]/.test(fact.proof_jti)
      || typeof fact.intent_hash !== 'string' || fact.intent_hash.length !== 71 || !/^sha256:[0-9a-f]{64}$/.test(fact.intent_hash)
      || FACT.slice(7).some(key => !safeTime(fact[key]))
      || fact.proof_iat_ms % 1000 !== 0 || fact.replay_expires_at_ms !== fact.proof_iat_ms + 61000
      || fact.verified_upper_bound_ms < fact.verified_now_ms || fact.verified_upper_bound_ms - fact.verified_now_ms > 1000
      || fact.proof_iat_ms > fact.verified_upper_bound_ms || fact.verified_upper_bound_ms - fact.proof_iat_ms > 60000
      || fact.token_expires_at_ms <= fact.verified_upper_bound_ms) invalid();
  return Object.freeze(fact);
}

export function challengeDeadline(value) {
  const { deadlineAt } = record(value, ['deadlineAt']);
  if (typeof deadlineAt !== 'number' || !Number.isFinite(deadlineAt)) invalid();
  const remaining = deadlineAt - performance.now();
  if (remaining <= 0 || remaining > 5000) invalid();
  return deadlineAt;
}
