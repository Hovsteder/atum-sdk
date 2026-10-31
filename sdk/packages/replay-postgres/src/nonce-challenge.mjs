import { createHash, randomBytes } from 'node:crypto';
import { ReplayStoreError } from './store.mjs';
import { challengeConfig, challengeDeadline, challengeFact } from './nonce-challenge-validation.mjs';
import { createTransactionRunner } from './transaction.mjs';
import { readClock, safeTime } from './validation.mjs';

const unavailable = () => new ReplayStoreError();
const outcome = status => Object.freeze({ status });

export function createPostgresNonceChallengeStore(config) {
  const saved = challengeConfig(config);
  const transaction = createTransactionRunner(saved.connect, unavailable);

  function issueVerifiedNonce(input, options) {
    const fact = challengeFact(input, saved.binding);
    const deadlineAt = challengeDeadline(options);
    let previous = fact.verified_now_ms;
    let upper = fact.verified_upper_bound_ms;
    function observed(expiresAt) {
      const clock = readClock(saved.clock, unavailable, previous);
      previous = clock.now; upper = Math.max(upper, clock.upper);
      if (fact.token_expires_at_ms <= upper || fact.proof_iat_ms > upper || upper - fact.proof_iat_ms > 60000
          || (expiresAt !== undefined && expiresAt <= upper)) throw unavailable();
      return clock;
    }
    let initial; let expiresAt; let nonce; let hash; let lock;
    try {
      initial = observed();
      expiresAt = Math.min(initial.now + 30000, fact.token_expires_at_ms);
      if (!safeTime(expiresAt) || expiresAt <= upper) throw unavailable();
      nonce = randomBytes(32).toString('base64url');
      hash = createHash('sha256').update(`atum.dpop.nonce.v1\n${nonce}`, 'ascii').digest('hex');
      lock = createHash('sha256').update('atum.dpop.nonce.capacity.v1\n', 'ascii')
        .update(JSON.stringify([fact.issuer, fact.audience, fact.agent_key_thumbprint]), 'utf8').digest().readBigInt64BE(0).toString();
    } catch { return Promise.reject(unavailable()); }

    return transaction(async query => {
      observed(expiresAt);
      await query('SELECT pg_advisory_xact_lock($1::bigint)', [lock]);
      const clock = observed(expiresAt);
      const counted = await query('SELECT count(*)::text AS count FROM atum_request_proofs.nonces WHERE issuer = $1 AND audience = $2 AND agent_key_thumbprint = $3 AND consumed_at_ms IS NULL AND expires_at_ms > $4',
        [fact.issuer, fact.audience, fact.agent_key_thumbprint, clock.lower]);
      observed(expiresAt);
      const count = counted.rows?.[0]?.count;
      if (counted.rowCount !== 1 || typeof count !== 'string' || !/^(0|[1-9][0-9]{0,15})$/.test(count) || !Number.isSafeInteger(Number(count))) throw unavailable();
      if (Number(count) >= saved.cap) return { commit: false, value: outcome('rate_limited') };
      const inserted = await query('INSERT INTO atum_request_proofs.proofs (issuer, audience, agent_key_thumbprint, proof_jti, intent_hash, first_seen_ms, expires_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING',
        [fact.issuer, fact.audience, fact.agent_key_thumbprint, fact.proof_jti, fact.intent_hash, previous, fact.replay_expires_at_ms]);
      observed(expiresAt);
      if (inserted.rowCount === 0) return { commit: false, value: outcome('replayed') };
      if (inserted.rowCount !== 1) throw unavailable();
      const issued = await query('INSERT INTO atum_request_proofs.nonces (nonce_hash,issuer,audience,agent_key_thumbprint,endpoint_url,issued_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7)',
        [hash, fact.issuer, fact.audience, fact.agent_key_thumbprint, fact.endpoint_url, initial.now, expiresAt]);
      if (issued.rowCount !== 1) throw unavailable();
      observed(expiresAt);
      return { commit: true, value: Object.freeze({ status: 'issued', nonce, expires_at_ms: expiresAt }), postCommit: () => { observed(expiresAt); } };
    }, deadlineAt);
  }

  return Object.freeze({ issueVerifiedNonce });
}
