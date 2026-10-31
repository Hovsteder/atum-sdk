import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import { createPostgresNonceChallengeStore } from '../../src/nonce-challenge.mjs';
import { ReplayStoreError } from '../../src/store.mjs';

const NOW = 1_700_000_000_000;
const binding = { issuer: 'https://issuer.example', audience: 'atum:test', endpoint_url: 'https://api.example/invoke' };
const fact = { nonce_issue_only: true, ...binding, agent_key_thumbprint: Buffer.alloc(32, 4).toString('base64url'),
  proof_jti: 'initial-proof-jti-0001', intent_hash: `sha256:${'a'.repeat(64)}`, token_expires_at_ms: NOW + 20_000,
  proof_iat_ms: NOW, replay_expires_at_ms: NOW + 61_000, verified_now_ms: NOW, verified_upper_bound_ms: NOW };
const options = (ms = 500) => ({ deadlineAt: performance.now() + ms });

function fixture({ count = 0, duplicate = false, hook } = {}) {
  const state = { now: NOW, uncertainty: 0, healthy: true };
  const queries = [];
  let released; let acquired = 0;
  const client = Object.assign(new EventEmitter(), {
    async query(sql, values) {
      queries.push({ sql, values });
      if (hook) await hook(sql, state);
      if (sql.includes('count(*)')) return { rowCount: 1, rows: [{ count: String(count) }] };
      if (sql.includes('INSERT INTO atum_request_proofs.proofs')) return { rowCount: duplicate ? 0 : 1, rows: [] };
      return { rowCount: 1, rows: [] };
    },
    release(error) { released = error; },
  });
  const pool = { connect(callback) { acquired++; callback(null, client); } };
  const config = { pool, clock: () => ({ now_ms: state.now, uncertainty_ms: state.uncertainty, healthy: state.healthy }), binding, maxActiveNoncesPerKey: 2 };
  return { config, client, state, queries, get released() { return released; }, get acquired() { return acquired; } };
}

test('authenticated nonce issuance records actual JTI/intent and caps nonce at token expiry', async () => {
  const f = fixture();
  const store = createPostgresNonceChallengeStore(f.config);
  assert.deepEqual(Object.keys(store), ['issueVerifiedNonce']);
  const result = await store.issueVerifiedNonce(fact, options());
  assert.equal(result.status, 'issued'); assert.equal(Object.isFrozen(result), true);
  assert.equal(Buffer.from(result.nonce, 'base64url').length, 32);
  assert.equal(result.expires_at_ms, fact.token_expires_at_ms);
  const proof = f.queries.find(q => q.sql.includes('INSERT INTO atum_request_proofs.proofs'));
  assert.deepEqual(proof.values.slice(0, 5), [binding.issuer, binding.audience, fact.agent_key_thumbprint, fact.proof_jti, fact.intent_hash]);
  const insert = f.queries.find(q => q.sql.includes('INSERT INTO atum_request_proofs.nonces'));
  assert.notEqual(insert.values[0], result.nonce);
  assert.equal(insert.values[0].length, 64);
  assert.equal(f.queries.at(-1).sql, 'COMMIT'); assert.equal(f.released, undefined);
});

test('capacity counts across endpoints with lower time and rolls back without eviction', async () => {
  const f = fixture({ count: 2 }); f.state.uncertainty = 250;
  const result = await createPostgresNonceChallengeStore(f.config).issueVerifiedNonce(fact, options());
  assert.deepEqual(result, { status: 'rate_limited' });
  const count = f.queries.find(q => q.sql.includes('count(*)'));
  assert.deepEqual(count.values, [binding.issuer, binding.audience, fact.agent_key_thumbprint, NOW - 250]);
  assert.doesNotMatch(count.sql, /endpoint_url|FOR UPDATE/);
  assert.equal(f.queries.some(q => /INSERT|DELETE/.test(q.sql)), false);
  assert.equal(f.queries.at(-1).sql, 'ROLLBACK');
});

test('repeated initial JTI creates no nonce and returns only replayed', async () => {
  const f = fixture({ duplicate: true });
  assert.deepEqual(await createPostgresNonceChallengeStore(f.config).issueVerifiedNonce(fact, options()), { status: 'replayed' });
  assert.equal(f.queries.some(q => q.sql.includes('INSERT INTO atum_request_proofs.nonces')), false);
  assert.equal(f.queries.at(-1).sql, 'ROLLBACK');
});

test('malformed or wrong-bound facts and deadlines reject before acquisition', () => {
  const f = fixture(); const store = createPostgresNonceChallengeStore(f.config);
  for (const changes of [{ nonce_issue_only: false }, { proof_verified: true }, { endpoint_url: 'https://other.example/invoke' },
    { agent_key_thumbprint: `${fact.agent_key_thumbprint}=` }, { proof_iat_ms: NOW + 1 },
    { replay_expires_at_ms: NOW + 62_000 }, { verified_upper_bound_ms: NOW - 1 }, { token_expires_at_ms: NOW }]) {
    assert.throws(() => store.issueVerifiedNonce({ ...fact, ...changes }, options()), TypeError);
  }
  for (const value of [{}, { deadlineAt: performance.now() - 1 }, { deadlineAt: performance.now() + 5001 }, { deadlineAt: Infinity }]) {
    assert.throws(() => store.issueVerifiedNonce(fact, value), TypeError);
  }
  let coercions = 0;
  assert.throws(() => store.issueVerifiedNonce(fact, { deadlineAt: { valueOf() { coercions++; throw new Error('private input'); } } }),
    error => error instanceof TypeError && error.message === 'invalid input');
  assert.equal(coercions, 0);
  for (const cap of [0, 65, 1.5]) assert.throws(() => createPostgresNonceChallengeStore({ ...f.config, maxActiveNoncesPerKey: cap }), TypeError);
  assert.equal(f.acquired, 0);
});

test('facts are copied before acquisition and accessors never execute', async () => {
  const f = fixture(); let acquire;
  f.config.pool.connect = callback => { acquire = () => callback(null, f.client); };
  const store = createPostgresNonceChallengeStore(f.config);
  let reads = 0;
  assert.throws(() => store.issueVerifiedNonce({ ...fact, get proof_jti() { reads++; return fact.proof_jti; } }, options()), TypeError);
  assert.equal(reads, 0);
  const mutable = { ...fact }; const pending = store.issueVerifiedNonce(mutable, options());
  mutable.proof_jti = 'changed-initial-jti'; acquire();
  await pending;
  assert.equal(f.queries.find(q => q.sql.includes('INSERT INTO atum_request_proofs.proofs')).values[3], fact.proof_jti);
});

test('clock expiry after advisory lock or final insert never commits issuance', async () => {
  for (const marker of ['pg_advisory_xact_lock', 'INSERT INTO atum_request_proofs.nonces']) {
    const f = fixture({ hook(sql, state) { if (sql.includes(marker)) state.now = fact.token_expires_at_ms; } });
    await assert.rejects(createPostgresNonceChallengeStore(f.config).issueVerifiedNonce(fact, options()), ReplayStoreError);
    assert.equal(f.queries.some(q => q.sql === 'COMMIT'), false);
  }
});

test('late or lost COMMIT response is unavailable and never returns an issued nonce', async () => {
  for (const mode of ['clock', 'loss']) {
    const f = fixture({ hook(sql, state) { if (sql === 'COMMIT') { if (mode === 'loss') throw new Error('private SQL/token'); state.now = fact.token_expires_at_ms; } } });
    await assert.rejects(createPostgresNonceChallengeStore(f.config).issueVerifiedNonce(fact, options()), error => error instanceof ReplayStoreError && error.message === 'temporarily_unavailable');
    assert.equal(f.queries.some(q => q.sql === 'COMMIT'), true); assert.equal(f.released instanceof Error, true);
  }
});

test('absolute budget bounds stalled SQL and destroys without queueing rollback', async () => {
  const f = fixture({ hook(sql) { if (sql.includes('pg_advisory_xact_lock')) return new Promise(() => {}); } });
  const start = performance.now();
  await assert.rejects(createPostgresNonceChallengeStore(f.config).issueVerifiedNonce(fact, options(25)), ReplayStoreError);
  assert.ok(performance.now() - start < 500);
  assert.equal(f.released instanceof Error, true);
  assert.equal(f.queries.some(q => q.sql === 'ROLLBACK' || q.sql === 'COMMIT'), false);
});
