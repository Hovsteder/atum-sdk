// Two separate processes with a whole PostgreSQL restart between them, run by test-postgres.py.
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import pg from 'pg';
import { createPostgresReplayStore } from '../src/store.mjs';
import { createPostgresNonceChallengeStore } from '../src/nonce-challenge.mjs';
import { testConnection } from './test-connection.mjs';

const [phase, stateFile] = process.argv.slice(2);
if (!['write', 'read'].includes(phase) || !stateFile?.startsWith('/tmp/atum-replay-pg-')) throw new Error('Use test harness.');
const pool = new pg.Pool(testConnection());
const binding = { issuer: 'https://restart.issuer.invalid', audience: 'restart-resource', endpoint_url: 'https://restart.resource.invalid/operation' };
const now = Date.UTC(2026, 9, 30, 12);
const key = Buffer.alloc(32, 73).toString('base64url');
const store = createPostgresReplayStore({ pool, binding, clock: () => ({ now_ms: now, uncertainty_ms: 0, healthy: true }) });
const challenges = createPostgresNonceChallengeStore({ pool, binding, maxActiveNoncesPerKey: 4,
  clock: () => ({ now_ms: now, uncertainty_ms: 0, healthy: true }) });
const initial = { nonce_issue_only: true, ...binding, agent_key_thumbprint: key, proof_jti: 'restart-initial-jti-01',
  intent_hash: `sha256:${'f'.repeat(64)}`, token_expires_at_ms: now + 120_000, proof_iat_ms: now,
  replay_expires_at_ms: now + 61_000, verified_now_ms: now, verified_upper_bound_ms: now };
const input = (nonce, jti) => ({ ...binding, agent_key_thumbprint: key, proof_jti: jti, nonce,
  intent_hash: `sha256:${'f'.repeat(64)}`, now_upper_bound_ms: now, replay_expires_at_ms: now + 61_000 });
try {
  if (phase === 'write') {
    const used = await store.issueNonce({ agent_key_thumbprint: key });
    const pending = await store.issueNonce({ agent_key_thumbprint: key });
    const usedInput = input(used.nonce, 'restart-used-jti-0001');
    const pendingInput = input(pending.nonce, 'restart-fresh-jti-001');
    assert.equal(await store.consume(usedInput), true);
    const challenged = await challenges.issueVerifiedNonce(initial, { deadlineAt: performance.now() + 1000 });
    assert.equal(challenged.status, 'issued');
    const challengeInput = input(challenged.nonce, 'restart-continuation-jti');
    await writeFile(stateFile, JSON.stringify({ usedInput, pendingInput, challengeInput }), { flag: 'wx', mode: 0o600 });
    console.log('restart write: consumed marker, unused nonce and authenticated initial marker/nonce persisted');
  } else {
    const state = JSON.parse(await readFile(stateFile, 'utf8'));
    assert.equal(await store.consume(state.usedInput), false);
    assert.equal(await store.consume(state.pendingInput), true);
    assert.equal(await store.consume(state.pendingInput), false);
    assert.deepEqual(await challenges.issueVerifiedNonce(initial, { deadlineAt: performance.now() + 1000 }), { status: 'replayed' });
    assert.equal(await store.consume({ ...state.challengeInput, proof_jti: initial.proof_jti }), false);
    assert.equal(await store.consume(state.challengeInput), true);
    assert.equal(await store.consume(state.challengeInput), false);
    console.log('restart read: old proof and initial JTI rejected, both pending nonces consumed once');
  }
} finally { await pool.end(); }
