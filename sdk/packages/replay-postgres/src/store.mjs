import { createHash, randomBytes } from 'node:crypto';
import { configSnapshot, consumeSnapshot, databaseTime, issueSnapshot, pruneSnapshot, readClock, safeTime } from './validation.mjs';
import { createTransactionRunner } from './transaction.mjs';

export class ReplayStoreError extends Error {
  constructor() { super('temporarily_unavailable'); this.name = 'ReplayStoreError'; this.code = 'temporarily_unavailable'; }
}

const unavailable = () => new ReplayStoreError();
const nonceHash = (nonce) => createHash('sha256').update(`atum.dpop.nonce.v1\n${nonce}`, 'ascii').digest('hex');

function matchingNonce(row, input, hash) {
  return row && row.nonce_hash === hash && row.consumed_at_ms === null && row.issuer === input.issuer && row.audience === input.audience
    && row.agent_key_thumbprint === input.agent_key_thumbprint && row.endpoint_url === input.endpoint_url && databaseTime(row.expires_at_ms) !== null;
}

function fresh(input, expiresAt, upper) {
  return expiresAt > upper && input.replay_expires_at_ms - 1000 >= upper && input.replay_expires_at_ms - 61_000 <= upper;
}

export function createPostgresReplayStore(config) {
  const binding = configSnapshot(config);
  const connect = config.pool.connect.bind(config.pool);
  const clock = config.clock;
  const transaction = createTransactionRunner(connect, unavailable);

  function issueNonce(input) {
    const request = issueSnapshot(input);
    let initial;
    try { initial = readClock(clock, unavailable); } catch { return Promise.reject(unavailable()); }
    const expiresAt = initial.now + 30_000;
    if (!safeTime(expiresAt) || expiresAt <= initial.upper) return Promise.reject(unavailable());
    let nonce;
    try { nonce = randomBytes(32).toString('base64url'); } catch { return Promise.reject(unavailable()); }
    const hash = nonceHash(nonce);
    let beforeCommit;
    return transaction(async (query) => {
      const inserted = await query('INSERT INTO atum_request_proofs.nonces (nonce_hash, issuer, audience, agent_key_thumbprint, endpoint_url, issued_at_ms, expires_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7)', [hash, binding.issuer, binding.audience, request.agent_key_thumbprint, binding.endpoint_url, initial.now, expiresAt]);
      if (inserted.rowCount !== 1) throw unavailable();
      beforeCommit = readClock(clock, unavailable, initial.now);
      if (expiresAt <= beforeCommit.upper) return { commit: false, value: null };
      return { commit: true, value: Object.freeze({ nonce, expires_at_ms: expiresAt }), postCommit: () => {
        const committed = readClock(clock, unavailable, beforeCommit.now);
        if (expiresAt <= committed.upper) throw unavailable();
      } };
    }).then((result) => { if (result === null) throw unavailable(); return result; });
  }

  function consume(input) {
    const request = consumeSnapshot(input);
    if (request === null || request.issuer !== binding.issuer || request.audience !== binding.audience || request.endpoint_url !== binding.endpoint_url) return Promise.resolve(false);
    let initial;
    try { initial = readClock(clock, unavailable); } catch { return Promise.reject(unavailable()); }
    const hash = nonceHash(request.nonce);
    return transaction(async (query) => {
      const selected = await query('SELECT nonce_hash, issuer, audience, agent_key_thumbprint, endpoint_url, expires_at_ms, consumed_at_ms FROM atum_request_proofs.nonces WHERE nonce_hash = $1 FOR UPDATE', [hash]);
      let observed = readClock(clock, unavailable, initial.now);
      let upper = Math.max(request.now_upper_bound_ms, observed.upper);
      const row = selected.rows?.[0];
      const expiresAt = databaseTime(row?.expires_at_ms);
      if (!matchingNonce(row, request, hash) || !fresh(request, expiresAt, upper)) return { commit: false, value: false };
      const inserted = await query('INSERT INTO atum_request_proofs.proofs (issuer, audience, agent_key_thumbprint, proof_jti, intent_hash, first_seen_ms, expires_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING', [binding.issuer, binding.audience, request.agent_key_thumbprint, request.proof_jti, request.intent_hash, observed.now, request.replay_expires_at_ms]);
      if (inserted.rowCount !== 1) return { commit: false, value: false };
      const consumed = await query('UPDATE atum_request_proofs.nonces SET consumed_at_ms = $2 WHERE nonce_hash = $1 AND consumed_at_ms IS NULL', [hash, observed.now]);
      if (consumed.rowCount !== 1) throw unavailable();
      observed = readClock(clock, unavailable, observed.now);
      upper = Math.max(upper, observed.upper);
      if (!fresh(request, expiresAt, upper)) return { commit: false, value: false };
      return { commit: true, value: true, postCommit: () => {
        const committed = readClock(clock, unavailable, observed.now);
        if (!fresh(request, expiresAt, Math.max(upper, committed.upper))) throw unavailable();
      } };
    });
  }

  function prune(input) {
    const limit = pruneSnapshot(input);
    let initial;
    try { initial = readClock(clock, unavailable); } catch { return Promise.reject(unavailable()); }
    return transaction(async (query) => {
      const nonces = await query('WITH candidates AS (SELECT nonce_hash FROM atum_request_proofs.nonces WHERE issuer = $1 AND audience = $2 AND endpoint_url = $3 AND expires_at_ms < $4 ORDER BY expires_at_ms FOR UPDATE SKIP LOCKED LIMIT $5) DELETE FROM atum_request_proofs.nonces n USING candidates c WHERE n.nonce_hash = c.nonce_hash', [binding.issuer, binding.audience, binding.endpoint_url, initial.lower, limit]);
      const proofs = await query('WITH candidates AS (SELECT issuer, audience, agent_key_thumbprint, proof_jti FROM atum_request_proofs.proofs WHERE issuer = $1 AND audience = $2 AND expires_at_ms < $3 ORDER BY expires_at_ms FOR UPDATE SKIP LOCKED LIMIT $4) DELETE FROM atum_request_proofs.proofs p USING candidates c WHERE p.issuer = c.issuer AND p.audience = c.audience AND p.agent_key_thumbprint = c.agent_key_thumbprint AND p.proof_jti = c.proof_jti', [binding.issuer, binding.audience, initial.lower, limit]);
      const beforeCommit = readClock(clock, unavailable, initial.now);
      if (beforeCommit.lower < initial.lower) throw unavailable();
      return { commit: true, value: Object.freeze({ nonces_deleted: nonces.rowCount ?? 0, proofs_deleted: proofs.rowCount ?? 0 }), postCommit: () => { readClock(clock, unavailable, beforeCommit.now); } };
    });
  }

  return Object.freeze({ issueNonce, consume, prune });
}
