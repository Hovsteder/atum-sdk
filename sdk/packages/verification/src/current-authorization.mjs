/** Fresh proof + authority composition. It verifies permission; it never executes an effect. */
import { createAuthorityVerifier, AuthorityError } from './authority.mjs';
import { parseStrictJson } from './context.mjs';
import { VerificationError } from './errors.mjs';
import { createResourceClient } from './resource-client.mjs';
import { createVerifier } from './verifier.mjs';

const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, fields) => plain(value) && Object.keys(value).length === fields.size
  && Object.keys(value).every(key => fields.has(key));
const frozen = value => {
  if (Array.isArray(value)) return Object.freeze(value.map(frozen));
  if (plain(value)) return Object.freeze(Object.fromEntries(Object.entries(value).map(([key, item]) => [key, frozen(item)])));
  return value;
};

export async function createCurrentAuthorizationVerifier(config) {
  const fields = new Set(['registration', 'proof', 'authority', 'clock']);
  if (Object.hasOwn(config ?? {}, 'descriptor')) fields.add('descriptor');
  const credentialMode = Object.hasOwn(config?.authority ?? {}, 'serviceCredential');
  const authorityFields = credentialMode
    ? new Set(['issuerKeys', 'evidencePolicy', 'baseUrl', 'https', 'serviceCredential', 'timeoutMs', 'maxConcurrent'])
    : new Set(['issuerKeys', 'evidencePolicy', 'baseUrl', 'tls', 'timeoutMs', 'maxConcurrent']);
  if (!exact(config, fields) || typeof config.clock !== 'function'
      || !exact(config.proof, new Set(['issuerKeys', 'endpoint', 'replayStore']))
      || !exact(config.authority, authorityFields)) {
    throw new TypeError('invalid current authorization config');
  }
  const common = { registration: config.registration, clock: config.clock,
    ...(Object.hasOwn(config, 'descriptor') ? { descriptor: config.descriptor } : {}) };
  let proofVerifier; let authorityVerifier; let authorityClient;
  try {
    proofVerifier = await createVerifier({ ...common, issuerKeys: config.proof.issuerKeys,
      endpoint: config.proof.endpoint, replayStore: config.proof.replayStore });
    authorityVerifier = await createAuthorityVerifier({ ...common, issuerKeys: config.authority.issuerKeys,
      evidencePolicy: config.authority.evidencePolicy });
    authorityClient = createResourceClient({ registration: config.registration,
      ...(Object.hasOwn(config, 'descriptor') ? { descriptor: config.descriptor } : {}),
      baseUrl: config.authority.baseUrl,
      ...(credentialMode ? { https: config.authority.https, serviceCredential: config.authority.serviceCredential }
        : { tls: config.authority.tls }),
      timeoutMs: config.authority.timeoutMs, maxConcurrent: config.authority.maxConcurrent });
  } catch {
    try { await authorityClient?.close(); } catch { /* no active calls during construction */ }
    throw new TypeError('invalid current authorization config');
  }

  let closed = false;
  return Object.freeze({
    async verifyCurrent(protectedRequest) {
      if (closed) throw new VerificationError('temporarily_unavailable');
      let body;
      try {
        body = parseStrictJson(protectedRequest?.body, 32768);
        if (!exact(body, new Set(['context', 'action_request']))) throw new TypeError();
        body = frozen(structuredClone(body));
      } catch { throw new VerificationError('invalid_request'); }

      const proof = await proofVerifier.verifyProtectedRequest(protectedRequest);
      const request = { context: proof.context, action_request: body.action_request, client_id: proof.client_id };
      const snapshotAssertion = await authorityClient.snapshot(request);
      const snapshot = await authorityVerifier.verifyGrantSnapshot(
        snapshotAssertion, proof.context, body.action_request, proof.client_id);
      // `admit` is deliberately attempted once. An ambiguous transport result is
      // fenced for the caller; this path never retrieves or resubmits it.
      const admissionAssertion = await authorityClient.admit(request);
      const admission = await authorityVerifier.verifyAdmission(
        admissionAssertion, proof.context, body.action_request, { mode: 'accept' });
      if (admission.decision !== 'admitted' || admission.authorization_effect !== 'admission') {
        throw new AuthorityError(admission.reason);
      }
      return frozen({ authorization_effect: 'current_permission', requires_resource_acceptance: true,
        proof_verified: true, scoped_subject: proof.context.scoped_subject,
        agent_key_thumbprint: proof.context.agent_key_thumbprint, client_id: proof.client_id,
        context: proof.context, action_request: body.action_request, intent_hash: proof.intent_hash,
        proof_jti: proof.proof_jti, admission_id: admission.admission_id,
        permissions: snapshot.grant.permissions, grant_limit: snapshot.grant.grant_limit,
        token_expires_at_ms: proof.token_expires_at_ms,
        grant_expires_at_ms: snapshot.grant.grant_expires_at_ms,
        snapshot_valid_until_ms: snapshot.valid_until_ms,
        evaluated_at_ms: admission.evaluated_at_ms,
        evaluated_uncertainty_ms: admission.evaluated_uncertainty_ms,
        acceptance_expires_at_ms: admission.acceptance_expires_at_ms,
        first_submit_expires_at_ms: admission.first_submit_expires_at_ms });
    },
    async close() { if (!closed) { closed = true; await authorityClient.close(); } },
  });
}

export { AuthorityError } from './authority.mjs';
export { ResourceTransportError } from './resource-client.mjs';
export { VerificationError } from './errors.mjs';
