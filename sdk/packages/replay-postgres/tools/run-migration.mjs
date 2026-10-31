import { readFile } from 'node:fs/promises';
import pg from 'pg';
import { testConnection } from './test-connection.mjs';

const pool = new pg.Pool(testConnection());
try {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(await readFile(new URL('../migrations/001_nonce_replay.sql', import.meta.url), 'utf8'));
    await client.query(await readFile(new URL('../migrations/002_nonce_challenge_capacity.sql', import.meta.url), 'utf8'));
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { client.release(); }
  console.log('Disposable replay schema migrated.');
} finally { await pool.end(); }
