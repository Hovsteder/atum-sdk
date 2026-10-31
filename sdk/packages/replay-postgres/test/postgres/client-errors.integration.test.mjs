import assert from 'node:assert/strict';
import test from 'node:test';
import pg from 'pg';
import { createTransactionRunner } from '../../src/transaction.mjs';
import { ReplayStoreError } from '../../src/store.mjs';
import { testConnection } from '../../tools/test-connection.mjs';

test('terminated checked-out backend fails closed between queries and pool remains usable', { timeout: 8000 }, async () => {
  // testConnection accepts only this harness's new /tmp Unix-socket cluster.
  const pool = new pg.Pool({ ...testConnection(), max: 2 });
  const idleErrors = [];
  pool.on('error', error => idleErrors.push(error));
  let leased;
  const run = createTransactionRunner(callback => {
    return pool.connect((error, client) => {
      if (error) return callback(error);
      leased = client;
      callback(null, client);
    });
  }, () => new ReplayStoreError());
  try {
    await assert.rejects(run(async query => {
      await query('SELECT 1');
      const ended = new Promise(resolve => leased.once('end', resolve));
      const killed = await pool.query('SELECT pg_terminate_backend($1) AS terminated', [leased.processID]);
      assert.equal(killed.rows[0].terminated, true);
      await ended;
      return { commit: true, value: 'must not be returned' };
    }), error => error instanceof ReplayStoreError && error.code === 'temporarily_unavailable');
    assert.equal(idleErrors.length, 0, 'a Pool error listener alone is not the leased-client handler');
    assert.equal((await pool.query('SELECT 1 AS ok')).rows[0].ok, 1);
    assert.equal(pool.waitingCount, 0);
  } finally {
    await pool.end();
  }
});
