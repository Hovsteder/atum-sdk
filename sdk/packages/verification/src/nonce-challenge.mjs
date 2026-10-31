import { VerificationError } from './errors.mjs';
import { createProofValidator } from './proof-validation.mjs';

const OMITTED_NONCE_FIELDS = new Set(['jti', 'htm', 'htu', 'iat', 'ath', 'atum_intent_hash']);

function options(value) {
  const enteredAt = performance.now();
  let descriptors;
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError('invalid input');
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch { throw new TypeError('invalid input'); }
  const keys = Reflect.ownKeys(descriptors);
  const descriptor = descriptors.deadlineAt;
  if (keys.length !== 1 || keys[0] !== 'deadlineAt' || descriptor === undefined || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable
      || typeof descriptor.value !== 'number' || !Number.isFinite(descriptor.value) || descriptor.value <= enteredAt || descriptor.value > enteredAt + 5000) throw new TypeError('invalid input');
  return descriptor.value;
}

function bounded(deadlineAt, operation) {
  let timer;
  const elapsed = new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new VerificationError('temporarily_unavailable')), Math.max(0, Math.ceil(deadlineAt - performance.now())));
  });
  let validation;
  try { validation = operation(); } catch (error) { clearTimeout(timer); return Promise.reject(error); }
  return Promise.race([validation, elapsed]).finally(() => clearTimeout(timer));
}

export async function createNonceChallengeVerifier(config) {
  const validator = await createProofValidator(config);
  return Object.freeze({ async verifyNonceChallengeRequest(input, value) {
    const deadlineAt = options(value);
    const verified = await bounded(deadlineAt, () => validator.validate(input, OMITTED_NONCE_FIELDS, deadlineAt, true));
    const upper = verified.maximumUpper;
    if (verified.token_expires_at_ms <= upper || verified.proof_iat_ms > upper || upper - verified.proof_iat_ms > 60000) throw new VerificationError('invalid_proof');
    if (performance.now() >= deadlineAt) throw new VerificationError('temporarily_unavailable');
    return Object.freeze({ nonce_issue_only: true, issuer: verified.context.issuer, audience: verified.context.audience,
      endpoint_url: verified.endpoint_url, agent_key_thumbprint: verified.agent_key_thumbprint, proof_jti: verified.proof_jti,
      intent_hash: verified.intent_hash, token_expires_at_ms: verified.token_expires_at_ms, proof_iat_ms: verified.proof_iat_ms,
      replay_expires_at_ms: verified.replay_expires_at_ms, verified_now_ms: verified.finalClock.now, verified_upper_bound_ms: upper });
  } });
}

export { VerificationError };
