import { VerificationError } from './errors.mjs';
import { createProofValidator } from './proof-validation.mjs';

const FULL_PROOF_FIELDS = new Set(['jti', 'htm', 'htu', 'iat', 'ath', 'nonce', 'atum_intent_hash']);

export { VerificationError };

export async function createVerifier(config) {
  const configFields = new Set(['registration', 'issuerKeys', 'endpoint', 'clock', 'replayStore']);
  if (config === null || typeof config !== 'object' || Array.isArray(config) || Object.getPrototypeOf(config) !== Object.prototype
      || Object.keys(config).length !== configFields.size || Object.keys(config).some(key => !configFields.has(key))
      || typeof config.clock !== 'function' || config.replayStore === null || typeof config.replayStore !== 'object'
      || typeof config.replayStore.consume !== 'function' || !Array.isArray(config.issuerKeys) || !config.issuerKeys.length) throw new TypeError('invalid config');
  const consume = config.replayStore.consume.bind(config.replayStore);
  const validator = await createProofValidator({ registration: config.registration, issuerKeys: config.issuerKeys, endpoint: config.endpoint, clock: config.clock });
  return Object.freeze({ async verifyProtectedRequest(input) {
    try {
      const verified = await validator.validate(input, FULL_PROOF_FIELDS);
      let consumed;
      try {
        consumed = await consume({ issuer: verified.context.issuer, audience: verified.context.audience,
          agent_key_thumbprint: verified.agent_key_thumbprint, proof_jti: verified.proof_jti, nonce: verified.nonce,
          endpoint_url: verified.endpoint_url, intent_hash: verified.intent_hash, now_upper_bound_ms: verified.finalClock.upper,
          replay_expires_at_ms: verified.replay_expires_at_ms });
      } catch { throw new VerificationError('temporarily_unavailable'); }
      if (consumed !== true) throw new VerificationError('invalid_proof');
      validator.recheckAfterStorage(verified);
      return Object.freeze({ proof_verified: true, authorization_effect: 'none', requires_admission: true,
        context: verified.context, intent_hash: verified.intent_hash, client_id: verified.client_id,
        token_expires_at_ms: verified.token_expires_at_ms, proof_jti: verified.proof_jti });
    } catch (error) {
      if (error instanceof VerificationError) throw error;
      throw new VerificationError('invalid_proof');
    }
  } });
}
