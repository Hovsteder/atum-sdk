import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import pg from '../../../services/oauth/node_modules/pg/lib/index.js';

import { createUsageStore, initializeUsageSchema, UsageError } from '../usage-store.mjs';
import { createObservedClock } from '../observed-clock.mjs';
import { migratePostgresReplaySchema } from '../../../packages/replay-postgres/src/migrate.mjs';

const { Pool } = pg;
const databaseUrl = process.env.ATUM_EXAMPLE_DATABASE_URL;
if (!databaseUrl) throw new Error('ATUM_EXAMPLE_DATABASE_URL is required');

test('explicit replay migration is idempotent and rejects an altered installed schema', async () => {
  const pool = new Pool({ connectionString: databaseUrl, max: 2 });
  await migratePostgresReplaySchema(pool);
  await migratePostgresReplaySchema(pool);
  await pool.query('ALTER TABLE atum_request_proofs.nonces DROP CONSTRAINT nonces_check');
  await assert.rejects(migratePostgresReplaySchema(pool), /incompatible replay schema/);
  await pool.end();
});

test('resource clock advances only from a fresh monotonic observation and fails closed', t => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'atum-observed-clock-')); t.after(() => rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'clock.json'); let monotonic = 1_004_000_000n;
  writeFileSync(file, JSON.stringify({ healthy: true, now_ms: 1_800_000_000_000,
    observed_monotonic_ns: '1000000000', uncertainty_ms: 5 }));
  const clock = createObservedClock(file, { maxAgeMs: 1000, monotonic: () => monotonic });
  assert.deepEqual(clock(), { healthy: true, now_ms: 1_800_000_000_004, uncertainty_ms: 5 });
  monotonic = 2_100_000_001n;
  assert.equal(clock().healthy, false);
  writeFileSync(file, JSON.stringify({ healthy: true, now_ms: 1_800_000_000_003,
    observed_monotonic_ns: monotonic.toString(), uncertainty_ms: 5 }));
  assert.equal(clock().healthy, false);
});

const context = (operationId, { namespace = 'calendar-read', grantId = 'grant-calendar-1' } = {}) => ({ protocol_version: '0.1.0-draft.2',
  resource_profile_version: 'atum.service-actions.v1-draft.1', resource_profile_hash: `sha256:${'a'.repeat(64)}`,
  issuer: 'https://issuer.example/atum', audience: 'https://calendar.example/atum', environment: 'sandbox',
  tenant_id: 'calendar-tenant', resource_id: 'calendar-resource', quota_scope_id: 'calendar-quota',
  operation_namespace: namespace, scoped_subject: 'subject-calendar-1', operation_id: operationId,
  grant_id: grantId, grant_version: 1, policy_version: 'passkey-v1', agent_key_thumbprint: 'A'.repeat(43),
  consent_hash: `sha256:${'b'.repeat(64)}`, action_hash: `sha256:${'c'.repeat(64)}`,
  account_binding_id: null, account_binding_version: null, action: 'calendar.event.read' });

function authorization(operationId, intentHash = `sha256:${'1'.repeat(64)}`, options = {}) {
  return { context: context(operationId, options), admission_id: `admission-${operationId}`,
    intent_hash: intentHash, client_id: 'calendar-agent', permissions: [{ action: 'calendar.event.read' }],
    action_request: { action: 'calendar.event.read', parameters: { calendar_id: 'main', limit: 10 } },
    grant_limit: 2, token_expires_at_ms: 1_800_000_010_000, grant_expires_at_ms: 1_800_000_020_000,
    snapshot_valid_until_ms: 1_800_000_005_000, acceptance_expires_at_ms: 1_800_000_004_000,
    first_submit_expires_at_ms: 1_800_000_003_000 };
}

test('resource acceptance is durable, idempotent and enforces the original grant limit', async () => {
  let now = 1_800_000_000_000; const config = { clock: () => ({ now_ms: now, uncertainty_ms: 5, healthy: true }) };
  let pool = new Pool({ connectionString: databaseUrl, max: 2 });
  await initializeUsageSchema(pool);
  const store = createUsageStore(pool, config); let executions = 0;
  const run = async () => ({ events: [{ event_id: `event-${++executions}` }] });
  const first = await store.acceptAndRun(authorization('operation-1'), run);
  const replay = await store.acceptAndRun(authorization('operation-1'), run);
  assert.equal(first.replayed, false); assert.equal(replay.replayed, true);
  assert.deepEqual(replay.result, first.result); assert.equal(executions, 1);
  await store.acceptAndRun(authorization('operation-2'), run);
  await assert.rejects(store.acceptAndRun(authorization('operation-3'), run),
    error => error instanceof UsageError && error.code === 'grant_limit_exhausted');
  await assert.rejects(store.acceptAndRun(authorization('operation-1', `sha256:${'2'.repeat(64)}`), run),
    error => error instanceof UsageError && error.code === 'conflict');
  const changedContext = authorization('operation-1'); changedContext.context.action_hash = `sha256:${'d'.repeat(64)}`;
  await assert.rejects(store.acceptAndRun(changedContext, run),
    error => error instanceof UsageError && error.code === 'conflict');
  await pool.end();

  now = 1_800_000_000_100;
  pool = new Pool({ connectionString: databaseUrl, max: 1 });
  const afterRestart = await createUsageStore(pool, config).acceptAndRun(authorization('operation-1'), run);
  assert.equal(afterRestart.replayed, true); assert.deepEqual(afterRestart.result, first.result);
  const extended = authorization('operation-1');
  for (const field of ['token_expires_at_ms','grant_expires_at_ms','snapshot_valid_until_ms',
    'acceptance_expires_at_ms','first_submit_expires_at_ms']) extended[field] += 100_000;
  now = 1_800_000_003_000;
  await assert.rejects(createUsageStore(pool, config).acceptAndRun(extended, run),
    error => error instanceof UsageError && error.code === 'authorization_expired');
  now = 1_800_000_003_000;
  await assert.rejects(createUsageStore(pool, config).acceptAndRun(authorization('operation-4'), run),
    error => error instanceof UsageError && error.code === 'authorization_expired');
  await pool.end();
});

test('deadlines cover operation, insert and ambiguous commit while grant quota spans namespaces', async () => {
  let now = 1_800_000_000_000;
  const clock = () => ({ now_ms: now, uncertainty_ms: 5, healthy: true });
  const pool = new Pool({ connectionString: databaseUrl, max: 2 });
  await initializeUsageSchema(pool);
  const store = createUsageStore(pool, { clock });

  const invalidToken = authorization('deadline-invalid-token', undefined, { grantId: 'grant-deadline-invalid' });
  invalidToken.token_expires_at_ms = 0;
  await assert.rejects(store.acceptAndRun(invalidToken, async () => ({})),
    error => error instanceof UsageError && error.code === 'invalid_request');

  const slow = authorization('deadline-slow-operation', undefined, { grantId: 'grant-deadline-slow' });
  await assert.rejects(store.acceptAndRun(slow, async () => {
    now = slow.first_submit_expires_at_ms;
    return { events: [] };
  }), error => error instanceof UsageError && error.code === 'authorization_expired');

  now = 1_800_000_000_000;
  const firstNamespace = authorization('namespace-one', undefined, { grantId: 'grant-cross-namespace', namespace: 'calendar-read' });
  firstNamespace.grant_limit = 1;
  await store.acceptAndRun(firstNamespace, async () => ({ events: [] }));
  const secondNamespace = authorization('namespace-two', undefined, { grantId: 'grant-cross-namespace', namespace: 'calendar-admin' });
  secondNamespace.grant_limit = 1;
  await assert.rejects(store.acceptAndRun(secondNamespace, async () => ({ events: [] })),
    error => error instanceof UsageError && error.code === 'grant_limit_exhausted');

  const realConnect = pool.connect.bind(pool);
  const lateCommitPool = { async connect() {
    const client = await realConnect();
    return new Proxy(client, { get(target, property) {
      if (property !== 'query') return Reflect.get(target, property, target);
      return async (...args) => {
        const result = await target.query(...args);
        if (args[0] === 'COMMIT') now = 1_800_000_003_000;
        return result;
      };
    } });
  } };
  now = 1_800_000_000_000;
  const lateStore = createUsageStore(lateCommitPool, { clock });
  const late = authorization('deadline-late-commit', undefined, { grantId: 'grant-late-commit' });
  await assert.rejects(lateStore.acceptAndRun(late, async () => ({ events: [{ event_id: 'late' }] })),
    error => error instanceof UsageError && error.code === 'temporarily_unavailable');
  const saved = await pool.query("SELECT result_json FROM atum_example_calendar_usage WHERE operation_id='deadline-late-commit'");
  assert.equal(saved.rowCount, 1);
  assert.deepEqual(JSON.parse(saved.rows[0].result_json), { events: [{ event_id: 'late' }] });
  await assert.rejects(store.acceptAndRun(late, async () => { throw new Error('must not repeat'); }),
    error => error instanceof UsageError && error.code === 'authorization_expired');
  await pool.end();
});
