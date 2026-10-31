// Test harness only. Never resolve a DB target from DATABASE_URL or ordinary PG* variables.
export function testConnection() {
  const host = process.env.ATUM_REPLAY_TEST_SOCKET;
  if (typeof host !== 'string' || !/^\/tmp\/atum-replay-pg-[A-Za-z0-9_-]+\/socket(?![\s\S])/.test(host)
      || process.env.ATUM_REPLAY_TEST_PORT !== '5432') {
    throw new Error('Use the disposable Unix-socket replay test harness.');
  }
  return { host, port: 5432, database: 'atum_replay_test', user: 'postgres',
    connectionTimeoutMillis: 2000, query_timeout: 5000, idleTimeoutMillis: 1000, max: 16 };
}
