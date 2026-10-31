import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import { createPostgresReplayStore, ReplayStoreError } from '../../src/store.mjs';

const binding = Object.freeze({
  issuer: 'https://issuer.example',
  audience: 'atum:example',
  endpoint_url: 'https://api.example/proofs',
});
const thumbprint = 'A'.repeat(43);
const nonce = Buffer.alloc(32, 9).toString('base64url');
const nonceHash = createHash('sha256').update(`atum.dpop.nonce.v1\n${nonce}`, 'ascii').digest('hex');
const intent = `sha256:${'a'.repeat(64)}`;

function clock(now = 1_700_000_000_000) { return () => ({ now_ms: now, uncertainty_ms: 0, healthy: true }); }
function clocks(...samples) {
  let index = 0;
  return () => samples[Math.min(index++, samples.length - 1)];
}

function clientWith(script = []) {
  const queries = [];
  let released;
  const client = new EventEmitter();
  Object.assign(client, {
    async query(sql, values) {
      queries.push({ sql, values });
      const next = script.shift();
      if (next instanceof Error) throw next;
      return next ?? { rows: [], rowCount: 0 };
    },
    release(error) { released = error; },
  });
  return {
    queries,
    get released() { return released; },
    client,
    pool: { connect(callback) { callback(undefined, client); } },
  };
}

function consumeInput(overrides = {}) {
  return { issuer: binding.issuer, audience: binding.audience, agent_key_thumbprint: thumbprint,
    proof_jti: 'proof-jti-012345', nonce, endpoint_url: binding.endpoint_url, intent_hash: intent,
    now_upper_bound_ms: 1_700_000_000_000, replay_expires_at_ms: 1_700_000_061_000, ...overrides };
}

test('factory returns frozen public methods and does not import a driver', () => {
  const { pool } = clientWith();
  const store = createPostgresReplayStore({ pool, clock: clock(), binding });
  assert.equal(Object.isFrozen(store), true);
  assert.deepEqual(Object.keys(store).sort(), ['consume', 'issueNonce', 'prune']);
  assert.equal(typeof ReplayStoreError, 'function');
});

test('consume rejects a malformed input synchronously before acquiring a client', () => {
  const { pool } = clientWith();
  const store = createPostgresReplayStore({ pool, clock: clock(), binding });
  assert.throws(() => store.consume({}), TypeError);
});

test('consume returns false for a different configured binding without storage access', async () => {
  const fake = clientWith();
  const store = createPostgresReplayStore({ pool: fake.pool, clock: clock(), binding });
  assert.equal(await store.consume(consumeInput({ audience: 'other' })), false);
  assert.equal(fake.queries.length, 0);
});

test('consume commits only after atomically marking a valid nonce and proof', async () => {
  const fake = clientWith([
    { rows: [], rowCount: 0 }, { rows: [], rowCount: 0 },
    { rows: [{ nonce_hash: nonceHash, agent_key_thumbprint: thumbprint, issuer: binding.issuer,
      audience: binding.audience, endpoint_url: binding.endpoint_url, expires_at_ms: 1_700_000_030_000,
      consumed_at_ms: null }], rowCount: 1 },
    { rows: [], rowCount: 1 }, { rows: [], rowCount: 1 }, { rows: [], rowCount: 0 },
  ]);
  const store = createPostgresReplayStore({ pool: fake.pool, clock: clock(), binding });
  assert.equal(await store.consume(consumeInput()), true);
  assert.match(fake.queries.map(({ sql }) => sql).join('\n'), /BEGIN ISOLATION LEVEL READ COMMITTED/);
  assert.match(fake.queries.map(({ sql }) => sql).join('\n'), /INSERT INTO atum_request_proofs\.proofs/);
  assert.match(fake.queries.map(({ sql }) => sql).join('\n'), /UPDATE atum_request_proofs\.nonces/);
  assert.match(fake.queries.at(-1).sql, /COMMIT/);
  const proofInsert = fake.queries.find(({ sql }) => /INSERT INTO atum_request_proofs\.proofs/.test(sql));
  assert.equal(typeof proofInsert.values.at(-1), 'number');
  assert.equal(fake.released, undefined);
});

test('duplicate proof jti rolls back and leaves the nonce unused', async () => {
  const fake = clientWith([
    { rows: [], rowCount: 0 }, { rows: [], rowCount: 0 },
    { rows: [{ nonce_hash: nonceHash, agent_key_thumbprint: thumbprint, issuer: binding.issuer, audience: binding.audience,
      endpoint_url: binding.endpoint_url, expires_at_ms: 1_700_000_030_000, consumed_at_ms: null }], rowCount: 1 },
    { rows: [], rowCount: 0 }, { rows: [], rowCount: 0 },
  ]);
  const store = createPostgresReplayStore({ pool: fake.pool, clock: clock(), binding });
  assert.equal(await store.consume(consumeInput()), false);
  assert.equal(fake.queries.some(({ sql }) => /UPDATE atum_request_proofs\.nonces/.test(sql)), false);
  assert.match(fake.queries.at(-1).sql, /ROLLBACK/);
});

test('a nonce update that affects no row rolls back the proof marker and is unavailable', async () => {
  const fake = clientWith([
    { rows: [], rowCount: 0 }, { rows: [], rowCount: 0 },
    { rows: [{ nonce_hash: nonceHash, agent_key_thumbprint: thumbprint, issuer: binding.issuer, audience: binding.audience,
      endpoint_url: binding.endpoint_url, expires_at_ms: 1_700_000_030_000, consumed_at_ms: null }], rowCount: 1 },
    { rows: [], rowCount: 1 }, { rows: [], rowCount: 0 }, { rows: [], rowCount: 0 },
  ]);
  const store = createPostgresReplayStore({ pool: fake.pool, clock: clock(), binding });
  await assert.rejects(store.consume(consumeInput()), ReplayStoreError);
  assert.equal(fake.queries.some(({ sql }) => sql === 'COMMIT'), false);
  assert.match(fake.queries.at(-1).sql, /ROLLBACK/);
});

test('a proof that expires while COMMIT is delayed is reported unavailable after commit', async () => {
  const fake = clientWith([
    { rows: [], rowCount: 0 }, { rows: [], rowCount: 0 },
    { rows: [{ nonce_hash: nonceHash, agent_key_thumbprint: thumbprint, issuer: binding.issuer, audience: binding.audience,
      endpoint_url: binding.endpoint_url, expires_at_ms: 1_700_000_030_000, consumed_at_ms: null }], rowCount: 1 },
    { rows: [], rowCount: 1 }, { rows: [], rowCount: 1 }, { rows: [], rowCount: 0 },
  ]);
  const store = createPostgresReplayStore({ pool: fake.pool, binding, clock: clocks(
    { now_ms: 1_700_000_000_000, uncertainty_ms: 0, healthy: true },
    { now_ms: 1_700_000_000_000, uncertainty_ms: 0, healthy: true },
    { now_ms: 1_700_000_000_000, uncertainty_ms: 0, healthy: true },
    { now_ms: 1_700_000_061_001, uncertainty_ms: 0, healthy: true },
  ) });
  await assert.rejects(store.consume(consumeInput()), ReplayStoreError);
  assert.equal(fake.queries.at(-1).sql, 'COMMIT');
});

test('query failures are sanitized and release an uncertain connection', async () => {
  const fake = clientWith([new Error('postgres://secret.example/atum nonce=leak')]);
  const store = createPostgresReplayStore({ pool: fake.pool, clock: clock(), binding });
  await assert.rejects(store.consume(consumeInput()), (error) => error instanceof ReplayStoreError
    && error.code === 'temporarily_unavailable' && !error.message.includes('secret') && !error.message.includes('leak'));
  assert.equal(fake.released instanceof Error, true);
});

test('unhealthy clocks are unavailable without acquiring a client', async () => {
  const fake = clientWith();
  const store = createPostgresReplayStore({ pool: fake.pool, clock: () => ({ now_ms: 1, uncertainty_ms: 0, healthy: false }), binding });
  await assert.rejects(() => store.prune({ limit: 1 }), ReplayStoreError);
  assert.equal(fake.queries.length, 0);
});

test('late acquisition and a hung query both destroy their clients without stray queries', async () => {
  const late = clientWith();
  let resolveLate;
  late.pool.connect = (callback) => { resolveLate = () => callback(undefined, late.client); };
  const lateStore = createPostgresReplayStore({ pool: late.pool, clock: clock(), binding });

  const hung = clientWith();
  hung.client.query = async (sql, values) => {
    hung.queries.push({ sql, values });
    return new Promise(() => {});
  };
  const hungStore = createPostgresReplayStore({ pool: hung.pool, clock: clock(), binding });

  const lateResult = assert.rejects(lateStore.prune({ limit: 1 }), ReplayStoreError);
  const hungResult = assert.rejects(hungStore.prune({ limit: 1 }), ReplayStoreError);
  setTimeout(resolveLate, 1100);
  await Promise.all([lateResult, hungResult]);
  assert.equal(late.queries.length, 0);
  assert.equal(late.released instanceof Error, true);
  assert.deepEqual(hung.queries.map(({ sql }) => sql), ['BEGIN ISOLATION LEVEL READ COMMITTED']);
  assert.equal(hung.released instanceof Error, true);
});

test('a lost commit response is unavailable and never resolves true', async () => {
  const fake = clientWith([
    { rows: [], rowCount: 0 }, { rows: [], rowCount: 0 },
    { rows: [{ nonce_hash: nonceHash, agent_key_thumbprint: thumbprint, issuer: binding.issuer, audience: binding.audience,
      endpoint_url: binding.endpoint_url, expires_at_ms: 1_700_000_030_000, consumed_at_ms: null }], rowCount: 1 },
    { rows: [], rowCount: 1 }, { rows: [], rowCount: 1 }, new Error('lost commit response'), { rows: [], rowCount: 0 },
  ]);
  const store = createPostgresReplayStore({ pool: fake.pool, clock: clock(), binding });
  await assert.rejects(store.consume(consumeInput()), ReplayStoreError);
  assert.equal(fake.queries.some(({ sql }) => sql === 'COMMIT'), true);
  assert.equal(fake.released instanceof Error, true);
});

test('captures request and configured binding before a delayed pool acquisition', async () => {
  const fake = clientWith([
    { rows: [], rowCount: 0 }, { rows: [], rowCount: 0 },
    { rows: [{ nonce_hash: nonceHash, agent_key_thumbprint: thumbprint, issuer: binding.issuer, audience: binding.audience,
      endpoint_url: binding.endpoint_url, expires_at_ms: 1_700_000_030_000, consumed_at_ms: null }], rowCount: 1 },
    { rows: [], rowCount: 1 }, { rows: [], rowCount: 1 }, { rows: [], rowCount: 0 },
  ]);
  let resolveConnect;
  fake.pool.connect = (callback) => { resolveConnect = () => callback(undefined, fake.client); };
  const mutableBinding = { ...binding };
  const store = createPostgresReplayStore({ pool: fake.pool, clock: clock(), binding: mutableBinding });
  const request = consumeInput();
  const pending = store.consume(request);
  await Promise.resolve();
  request.proof_jti = 'changed-proof-jti';
  mutableBinding.issuer = 'https://changed.example';
  resolveConnect();
  assert.equal(await pending, true);
  const proofInsert = fake.queries.find(({ sql }) => /INSERT INTO atum_request_proofs\.proofs/.test(sql));
  assert.equal(proofInsert.values[0], binding.issuer);
  assert.equal(proofInsert.values[3], 'proof-jti-012345');
});

test('rejects malformed canonical fields and clock overflow before storage access', async () => {
  const fake = clientWith();
  const store = createPostgresReplayStore({ pool: fake.pool, clock: clock(), binding });
  assert.throws(() => store.consume(consumeInput({ nonce: `${nonce}=` })), TypeError);
  assert.throws(() => store.consume(consumeInput({ proof_jti: 'proof-jti-012345\n' })), TypeError);
  assert.throws(() => store.consume(consumeInput({ intent_hash: `${intent}\n` })), TypeError);
  const overflow = createPostgresReplayStore({ pool: fake.pool, binding,
    clock: () => ({ now_ms: 8_640_000_000_000_000, uncertainty_ms: 1, healthy: true }) });
  await assert.rejects(overflow.prune({ limit: 1 }), ReplayStoreError);
  assert.equal(fake.queries.length, 0);
});
