import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test, { after } from 'node:test';
import pg from 'pg';
import { createPostgresNonceChallengeStore } from '../../src/nonce-challenge.mjs';
import { createPostgresReplayStore, ReplayStoreError } from '../../src/store.mjs';
import { testConnection } from '../../tools/test-connection.mjs';

const NOW = 1_700_000_000_000;
const key = Buffer.alloc(32, 5).toString('base64url');
const pool = new pg.Pool(testConnection());
pool.on('error', () => {});
after(() => pool.end());
const options = (ms = 1000) => ({ deadlineAt: performance.now() + ms });

function fixture(name, endpoint = 'https://api.example/invoke', poolOverride = pool) {
  const binding = { issuer: `https://issuer.example/nonce-${process.pid}-${name}`, audience: 'atum:nonce-test', endpoint_url: endpoint };
  const state = { now: NOW, uncertainty: 0 };
  const clock = () => ({ now_ms: state.now, uncertainty_ms: state.uncertainty, healthy: true });
  const config = { pool: poolOverride, clock, binding, maxActiveNoncesPerKey: 2 };
  return { binding, state, clock, config, store: createPostgresNonceChallengeStore(config),
    fact(jti = 'initial-proof-jti-0001', changes = {}) {
      return { nonce_issue_only: true, ...binding, agent_key_thumbprint: key, proof_jti: jti,
        intent_hash: `sha256:${'a'.repeat(64)}`, token_expires_at_ms: NOW + 120_000,
        proof_iat_ms: NOW, replay_expires_at_ms: NOW + 61_000, verified_now_ms: NOW, verified_upper_bound_ms: NOW, ...changes };
    } };
}
async function counts(f) {
  return (await pool.query(`SELECT
    (SELECT count(*)::int FROM atum_request_proofs.nonces WHERE issuer=$1 AND audience=$2) AS nonces,
    (SELECT count(*)::int FROM atum_request_proofs.proofs WHERE issuer=$1 AND audience=$2) AS proofs`, [f.binding.issuer, f.binding.audience])).rows[0];
}
function continuation(f, nonce, jti) {
  return { ...f.binding, agent_key_thumbprint: key, proof_jti: jti, nonce,
    intent_hash: `sha256:${'a'.repeat(64)}`, now_upper_bound_ms: NOW, replay_expires_at_ms: NOW + 61_000 };
}
function wrapper(hook) {
  return { connect(callback) { pool.connect((error, client) => {
    if (error) return callback(error);
    const proxy = { query: async (...args) => { const result = await client.query(...args); await hook(args[0]); return result; },
      release: client.release.bind(client), on: client.on.bind(client), removeListener: client.removeListener.bind(client) };
    callback(null, proxy);
  }); } };
}

test('real PG initial JTI is shared with complete replay identity and fresh continuation consumes once', async () => {
  const f = fixture('shared');
  const issued = await f.store.issueVerifiedNonce(f.fact(), options());
  assert.equal(issued.status, 'issued');
  const replay = createPostgresReplayStore({ pool, clock: f.clock, binding: f.binding });
  assert.equal(await replay.consume(continuation(f, issued.nonce, f.fact().proof_jti)), false);
  assert.equal(await replay.consume(continuation(f, issued.nonce, 'continuation-proof-0001')), true);
  assert.equal(await replay.consume(continuation(f, issued.nonce, 'continuation-proof-0002')), false);
  assert.deepEqual(await counts(f), { nonces: 1, proofs: 2 });
});

test('concurrent initial JTI across eight pools issues one durable nonce', async () => {
  const f = fixture('race'); const pools = Array.from({ length: 8 }, () => new pg.Pool({ ...testConnection(), max: 1 }));
  for (const p of pools) p.on('error', () => {});
  try {
    const results = await Promise.all(pools.map(p => createPostgresNonceChallengeStore({ ...f.config, pool: p }).issueVerifiedNonce(f.fact(), options())));
    assert.equal(results.filter(r => r.status === 'issued').length, 1);
    assert.equal(results.filter(r => r.status === 'replayed').length, 7);
    assert.deepEqual(await counts(f), { nonces: 1, proofs: 1 });
  } finally { await Promise.all(pools.map(p => p.end())); }
});

test('capacity serializes across endpoint and token changes without evicting outstanding nonces', async () => {
  const a = fixture('capacity'); const b = fixture('capacity', 'https://api.example/other');
  const results = await Promise.all(Array.from({ length: 8 }, (_, i) => {
    const f = i % 2 ? a : b;
    return f.store.issueVerifiedNonce(f.fact(`different-initial-jti-${i}`, { token_expires_at_ms: NOW + 90_000 + i * 1000 }), options());
  }));
  assert.equal(results.filter(r => r.status === 'issued').length, 2);
  assert.equal(results.filter(r => r.status === 'rate_limited').length, 6);
  assert.deepEqual(await counts(a), { nonces: 2, proofs: 2 });
});

test('capacity uses healthy lower and released capacity retains prior rows until bounded pruning', async () => {
  const f = fixture('uncertainty'); const one = createPostgresNonceChallengeStore({ ...f.config, maxActiveNoncesPerKey: 1 });
  const first = await one.issueVerifiedNonce(f.fact(), options());
  f.state.now = first.expires_at_ms + 500; f.state.uncertainty = 1000;
  assert.deepEqual(await one.issueVerifiedNonce(f.fact('next-initial-jti-0001'), options()), { status: 'rate_limited' });
  f.state.now = first.expires_at_ms + 1001;
  assert.equal((await one.issueVerifiedNonce(f.fact('next-initial-jti-0001'), options())).status, 'issued');
  assert.deepEqual(await counts(f), { nonces: 2, proofs: 2 });
});

test('token cap applies and SQL failure rolls back initial marker with nonce atomically', async () => {
  const f = fixture('rollback', undefined, wrapper(sql => { if (sql.startsWith('INSERT INTO atum_request_proofs.nonces')) throw new Error('lost write'); }));
  await assert.rejects(f.store.issueVerifiedNonce(f.fact(), options()), ReplayStoreError);
  assert.deepEqual(await counts(f), { nonces: 0, proofs: 0 });
  const plain = fixture('rollback');
  const result = await plain.store.issueVerifiedNonce(plain.fact('token-cap-proof-jti-001', { token_expires_at_ms: NOW + 1000 }), options());
  assert.equal(result.expires_at_ms, NOW + 1000);
});

test('expiry after final SQL rolls back, while lost successful COMMIT remains durable and unavailable', async () => {
  for (const mode of ['final-sql', 'commit']) {
    let f;
    const wrapped = wrapper(sql => {
      if (mode === 'final-sql' && sql.startsWith('INSERT INTO atum_request_proofs.nonces')) f.state.now = NOW + 120_000;
      if (mode === 'commit' && sql === 'COMMIT') throw new Error('response lost after durable commit');
    });
    f = fixture(mode, undefined, wrapped);
    await assert.rejects(f.store.issueVerifiedNonce(f.fact(), options()), ReplayStoreError);
    assert.deepEqual(await counts(f), mode === 'commit' ? { nonces: 1, proofs: 1 } : { nonces: 0, proofs: 0 });
    if (mode === 'commit') {
      const retry = fixture(mode);
      assert.deepEqual(await retry.store.issueVerifiedNonce(retry.fact(), options()), { status: 'replayed' });
    }
  }
});

test('absolute budget expires behind a real advisory lock without later creating rows', async () => {
  const f = fixture('lock-budget'); const client = await pool.connect();
  const lock = createHash('sha256').update('atum.dpop.nonce.capacity.v1\n').update(JSON.stringify([f.binding.issuer, f.binding.audience, key])).digest().readBigInt64BE().toString();
  try {
    await client.query('BEGIN'); await client.query('SELECT pg_advisory_xact_lock($1::bigint)', [lock]);
    const start = performance.now();
    await assert.rejects(f.store.issueVerifiedNonce(f.fact(), options(50)), ReplayStoreError);
    assert.ok(performance.now() - start < 500);
    await client.query('ROLLBACK');
    assert.deepEqual(await counts(f), { nonces: 0, proofs: 0 });
    assert.equal((await f.store.issueVerifiedNonce(f.fact(), options())).status, 'issued');
  } finally { await client.query('ROLLBACK').catch(() => {}); client.release(); }
});
