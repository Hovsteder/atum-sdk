import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test, { after, before } from 'node:test';
import pg from 'pg';

import { createPostgresReplayStore, ReplayStoreError } from '../../src/store.mjs';

const { Pool } = pg;
const baseNow = 1_700_000_000_000;
const thumbprint = Buffer.alloc(32, 7).toString('base64url');
const intentHash = `sha256:${'a'.repeat(64)}`;
const scope = `pg${process.pid}`;
let pool;
let connection;

function requiredConnection() {
  const socket = process.env.ATUM_REPLAY_TEST_SOCKET;
  const port = process.env.ATUM_REPLAY_TEST_PORT;
  if (typeof socket !== 'string' || !/^\/tmp\/atum-replay-pg-[A-Za-z0-9_-]+\/socket$/.test(socket)) {
    throw new Error('ATUM_REPLAY_TEST_SOCKET must name this run\'s /tmp/atum-replay-pg-*/socket directory');
  }
  if (port !== '5432') {
    throw new Error('ATUM_REPLAY_TEST_PORT must be exactly 5432');
  }
  return Object.freeze({ host: socket, port: 5432, database: 'atum_replay_test', user: 'postgres' });
}

function bindingFor(name) {
  return Object.freeze({
    issuer: `https://issuer.example/${scope}-${name}`,
    audience: `atum-replay-${scope}-${name}`,
    endpoint_url: 'https://api.example/proofs',
  });
}

function makeStore(name, poolOverride = pool) {
  const state = { now: baseNow, healthy: true };
  const binding = bindingFor(name);
  const store = createPostgresReplayStore({
    pool: poolOverride,
    binding,
    clock: () => ({ now_ms: state.now, uncertainty_ms: 0, healthy: state.healthy }),
  });
  return { binding, state, store };
}

function consumeInput(binding, nonce, overrides = {}) {
  return {
    issuer: binding.issuer,
    audience: binding.audience,
    agent_key_thumbprint: thumbprint,
    proof_jti: `proof-jti-${scope}-012345`,
    nonce,
    endpoint_url: binding.endpoint_url,
    intent_hash: intentHash,
    now_upper_bound_ms: baseNow,
    replay_expires_at_ms: baseNow + 61_000,
    ...overrides,
  };
}

async function issue(store) {
  return store.issueNonce({ agent_key_thumbprint: thumbprint });
}

async function rowsFor(binding) {
  const result = await pool.query({
    text: `SELECT
      (SELECT count(*)::int FROM atum_request_proofs.nonces WHERE issuer = $1 AND audience = $2 AND endpoint_url = $3) AS nonces,
      (SELECT count(*)::int FROM atum_request_proofs.proofs WHERE issuer = $1 AND audience = $2) AS proofs`,
    values: [binding.issuer, binding.audience, binding.endpoint_url],
  });
  return result.rows[0];
}

function nonceHash(nonce) {
  return createHash('sha256').update(`atum.dpop.nonce.v1\n${nonce}`, 'ascii').digest('hex');
}

function pause(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function withNonceLock(nonce, run) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query({
      text: 'SELECT nonce_hash FROM atum_request_proofs.nonces WHERE nonce_hash = $1 FOR UPDATE',
      values: [nonceHash(nonce)],
    });
    return await run();
  } finally {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
  }
}

before(async () => {
  // Validate the runner-provided Unix socket before constructing a Pool, so these tests
  // can never inherit a developer's TCP/PG* destination.
  connection = requiredConnection();
  pool = new Pool({ ...connection, max: 12, idleTimeoutMillis: 500 });
  await pool.query('SELECT 1');
});

after(async () => {
  await pool?.end();
});

test('issues and consumes a nonce once with the real PostgreSQL adapter', async () => {
  const { binding, store } = makeStore('success');
  const issued = await issue(store);
  assert.match(issued.nonce, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(issued.expires_at_ms, baseNow + 30_000);
  assert.equal(await store.consume(consumeInput(binding, issued.nonce)), true);
  assert.deepEqual(await rowsFor(binding), { nonces: 1, proofs: 1 });
});

test('preserves a nonce for unknown and wrong-bound requests, then rejects reuse', async () => {
  const { binding, store } = makeStore('bindings');
  const issued = await issue(store);
  const unknown = Buffer.alloc(32, 99).toString('base64url');

  assert.equal(await store.consume(consumeInput(binding, unknown)), false);
  assert.equal(await store.consume(consumeInput(binding, issued.nonce, { agent_key_thumbprint: Buffer.alloc(32, 8).toString('base64url') })), false);
  assert.equal(await store.consume(consumeInput(binding, issued.nonce, { issuer: 'https://other.example' })), false);
  assert.equal(await store.consume(consumeInput(binding, issued.nonce, { audience: 'other-audience' })), false);
  assert.equal(await store.consume(consumeInput(binding, issued.nonce, { endpoint_url: 'https://api.example/other' })), false);
  assert.equal(await store.consume(consumeInput(binding, issued.nonce)), true);
  assert.equal(await store.consume(consumeInput(binding, issued.nonce, { proof_jti: `used-${scope}-proof-jti` })), false);
  assert.deepEqual(await rowsFor(binding), { nonces: 1, proofs: 1 });
});

test('rejects a nonce precisely at its expiry without writing a proof marker', async () => {
  const { binding, state, store } = makeStore('expiry');
  const issued = await issue(store);
  state.now = issued.expires_at_ms;
  assert.equal(await store.consume(consumeInput(binding, issued.nonce)), false);
  assert.deepEqual(await rowsFor(binding), { nonces: 1, proofs: 0 });
});

test('allows at most one concurrent consume of the same proof across eight pools', async () => {
  const { binding, store } = makeStore('same-proof');
  const issued = await issue(store);
  const workers = Array.from({ length: 8 }, () => {
    const workerPool = new Pool({ ...connection, max: 1 });
    return {
      pool: workerPool,
      store: createPostgresReplayStore({
        pool: workerPool,
        binding,
        clock: () => ({ now_ms: baseNow, uncertainty_ms: 0, healthy: true }),
      }),
    };
  });
  try {
    const input = consumeInput(binding, issued.nonce);
    const results = await Promise.all(workers.map(({ store: worker }) => worker.consume(input)));
    assert.equal(results.filter(Boolean).length, 1);
  } finally {
    await Promise.all(workers.map(({ pool: workerPool }) => workerPool.end()));
  }
  assert.deepEqual(await rowsFor(binding), { nonces: 1, proofs: 1 });
});

test('allows at most one concurrent consume of the same nonce with different proofs', async () => {
  const { binding, store } = makeStore('same-nonce');
  const issued = await issue(store);
  const results = await Promise.all([
    store.consume(consumeInput(binding, issued.nonce, { proof_jti: `same-nonce-a-${scope}` })),
    store.consume(consumeInput(binding, issued.nonce, { proof_jti: `same-nonce-b-${scope}` })),
  ]);
  assert.equal(results.filter(Boolean).length, 1);
  assert.deepEqual(await rowsFor(binding), { nonces: 1, proofs: 1 });
});

test('keeps the losing nonce usable when the same proof races across two nonces', async () => {
  const { binding, store } = makeStore('same-jti');
  const first = await issue(store);
  const second = await issue(store);
  const sharedJti = `same-jti-${scope}-012345`;
  const firstInput = consumeInput(binding, first.nonce, { proof_jti: sharedJti });
  const secondInput = consumeInput(binding, second.nonce, { proof_jti: sharedJti });
  const results = await Promise.all([store.consume(firstInput), store.consume(secondInput)]);
  assert.equal(results.filter(Boolean).length, 1);
  const losingNonce = results[0] ? second.nonce : first.nonce;
  assert.equal(await store.consume(consumeInput(binding, losingNonce, { proof_jti: `fresh-jti-${scope}-012345` })), true);
  assert.deepEqual(await rowsFor(binding), { nonces: 2, proofs: 2 });
});

test('prunes only expired rows and respects its per-table limit', async () => {
  const { binding, state, store } = makeStore('prune');
  const expiredNonceHash = 'b'.repeat(64);
  const liveNonceHash = 'c'.repeat(64);
  await pool.query({
    text: `INSERT INTO atum_request_proofs.nonces
      (nonce_hash, issuer, audience, agent_key_thumbprint, endpoint_url, issued_at_ms, expires_at_ms)
      VALUES ($1, $2, $3, $4, $5, $6, $7), ($8, $2, $3, $4, $5, $6, $9)`,
    values: [expiredNonceHash, binding.issuer, binding.audience, thumbprint, binding.endpoint_url, baseNow - 10, baseNow - 1, liveNonceHash, baseNow + 1],
  });
  await pool.query({
    text: `INSERT INTO atum_request_proofs.proofs
      (issuer, audience, agent_key_thumbprint, proof_jti, intent_hash, first_seen_ms, expires_at_ms)
      VALUES ($1, $2, $3, $4, $5, $6, $7), ($1, $2, $3, $8, $5, $6, $9)`,
    values: [binding.issuer, binding.audience, thumbprint, `expired-prune-${scope}`, intentHash, baseNow - 10, baseNow - 1, `live-prune-${scope}`, baseNow + 1],
  });
  state.now = baseNow;
  assert.deepEqual(await store.prune({ limit: 1 }), { nonces_deleted: 1, proofs_deleted: 1 });
  assert.deepEqual(await rowsFor(binding), { nonces: 1, proofs: 1 });
});

test('does not change rows on malformed input or an unhealthy clock', async () => {
  const { binding, store } = makeStore('failure-input');
  const beforeRows = await rowsFor(binding);
  assert.throws(() => store.consume({}), TypeError);
  const unavailable = createPostgresReplayStore({
    pool,
    binding,
    clock: () => ({ now_ms: baseNow, uncertainty_ms: 0, healthy: false }),
  });
  await assert.rejects(() => unavailable.issueNonce({ agent_key_thumbprint: thumbprint }), (error) => error instanceof ReplayStoreError && error.code === 'temporarily_unavailable');
  await assert.rejects(() => unavailable.prune({ limit: 1 }), (error) => error instanceof ReplayStoreError && error.code === 'temporarily_unavailable');
  assert.deepEqual(await rowsFor(binding), beforeRows);
});

test('rolls back a real transaction when a query fails after proof insertion', async () => {
  const { binding, store: issuingStore } = makeStore('rollback');
  const issued = await issue(issuingStore);
  let injected = 0;
  const failingPool = {
    connect(callback) {
      return pool.connect((error, client) => {
        if (error) return callback(error);
        callback(null, {
        async query(query, values) {
          const sql = typeof query === 'string' ? query : query.text;
          if (/UPDATE atum_request_proofs\.nonces/.test(sql)) { injected += 1; throw new Error('injected update failure'); }
          return client.query(query, values);
        },
        on: client.on.bind(client),
        removeListener: client.removeListener.bind(client),
        release(error) { client.release(error); },
        });
      });
    },
  };
  const { store } = makeStore('rollback', failingPool);
  await assert.rejects(() => store.consume(consumeInput(binding, issued.nonce)), (error) => error instanceof ReplayStoreError && error.code === 'temporarily_unavailable');
  assert.equal(injected, 1, 'must reach the update after inserting a proof');
  assert.deepEqual(await rowsFor(binding), { nonces: 1, proofs: 0 });
});

test('rolls back a zero-row nonce update and permits the same input to retry', async () => {
  const { binding, store: issuingStore } = makeStore('zero-update');
  const issued = await issue(issuingStore);
  let injected = 0;
  const zeroUpdatePool = {
    connect(callback) {
      return pool.connect((error, client) => {
        if (error) return callback(error);
        callback(null, {
        async query(query, values) {
          const sql = typeof query === 'string' ? query : query.text;
          if (/UPDATE atum_request_proofs\.nonces/.test(sql)) { injected += 1; return { rows: [], rowCount: 0 }; }
          return client.query(query, values);
        },
        on: client.on.bind(client),
        removeListener: client.removeListener.bind(client),
        release(error) { client.release(error); },
        });
      });
    },
  };
  const { store } = makeStore('zero-update', zeroUpdatePool);
  const input = consumeInput(binding, issued.nonce);
  await assert.rejects(() => store.consume(input), (error) => error instanceof ReplayStoreError && error.code === 'temporarily_unavailable');
  assert.equal(injected, 1, 'must reach the zero-row update after inserting a proof');
  assert.deepEqual(await rowsFor(binding), { nonces: 1, proofs: 0 });
  assert.equal(await issuingStore.consume(input), true);
  assert.deepEqual(await rowsFor(binding), { nonces: 1, proofs: 1 });
});

test('can consume an issued nonce after closing and reopening the client pool', async () => {
  const binding = bindingFor('reopen');
  const issuingPool = new Pool({ ...connection, max: 2 });
  const issuingStore = createPostgresReplayStore({
    pool: issuingPool,
    binding,
    clock: () => ({ now_ms: baseNow, uncertainty_ms: 0, healthy: true }),
  });
  let issued;
  try {
    issued = await issue(issuingStore);
  } finally {
    await issuingPool.end();
  }
  const reopened = new Pool({ ...connection, max: 2 });
  try {
    const replayStore = createPostgresReplayStore({
      pool: reopened,
      binding,
      clock: () => ({ now_ms: baseNow, uncertainty_ms: 0, healthy: true }),
    });
    assert.equal(await replayStore.consume(consumeInput(binding, issued.nonce)), true);
  } finally {
    await reopened.end();
  }
});

test('returns unavailable after the configured lock timeout and preserves the nonce', async () => {
  const { binding, store } = makeStore('lock-timeout');
  const issued = await issue(store);
  await withNonceLock(issued.nonce, async () => {
    const pending = store.consume(consumeInput(binding, issued.nonce));
    const rejected = assert.rejects(pending, (error) => error instanceof ReplayStoreError && error.code === 'temporarily_unavailable');
    await pause(1_200);
    await rejected;
  });
  assert.equal(await store.consume(consumeInput(binding, issued.nonce)), true);
});

test('rechecks the clock after waiting for a nonce lock before committing', async () => {
  const { binding, state, store } = makeStore('clock-after-lock');
  const issued = await issue(store);
  let pending;
  await withNonceLock(issued.nonce, async () => {
    pending = store.consume(consumeInput(binding, issued.nonce));
    await pause(100);
    state.now = issued.expires_at_ms;
  });
  // Releasing the row lock lets consume observe the advanced clock before its commit.
  assert.equal(await pending, false);
  assert.deepEqual(await rowsFor(binding), { nonces: 1, proofs: 0 });
});
