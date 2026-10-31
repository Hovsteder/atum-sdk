import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import pg from 'pg';
import { createTransactionRunner } from '../../src/transaction.mjs';

class Client extends EventEmitter {
  constructor({ faultAt } = {}) {
    super();
    this.faultAt = faultAt;
    this.queries = [];
    this.releases = [];
  }

  query(sql) {
    this.queries.push(sql);
    if (sql === this.faultAt) {
      queueMicrotask(() => this.emit('error', new Error('socket lost')));
      return new Promise((resolve) => setImmediate(() => resolve({ rows: [], rowCount: 1 })));
    }
    return Promise.resolve({ rows: [], rowCount: 1 });
  }

  release(error) { this.releases.push(error); }
}

const unavailable = () => new Error('temporarily_unavailable');
const transactionFor = (client) => createTransactionRunner((callback) => callback(undefined, client), unavailable);
const commit = () => ({ commit: true, value: 'value' });

async function rejectsUnavailable(promise) {
  await assert.rejects(promise, (error) => error.message === 'temporarily_unavailable');
}

function packet(type, payload) {
  const header = Buffer.alloc(5);
  header.write(type);
  header.writeInt32BE(payload.length + 4, 1);
  return Buffer.concat([header, payload]);
}

class ParserStream extends EventEmitter {
  writable = true;
  setNoDelay() {} setKeepAlive() {} ref() {} unref() {}
  connect() { setImmediate(() => this.emit('connect')); }
  write() {
    if (!this.sent) {
      this.sent = true;
      setImmediate(() => this.emit('data', Buffer.concat([
        packet('R', Buffer.from([0, 0, 0, 0])),
        packet('Z', Buffer.from('I')),
        packet('E', Buffer.from('SFATAL\0C57P01\0Mterminating connection due to administrator command\0\0')),
      ])));
    }
    return true;
  }
  end() { this.destroy(); }
  destroy() { setImmediate(() => this.emit('close')); }
}

test('installs the checked-out listener before pg parses a same-chunk FATAL after ReadyForQuery', async () => {
  const pool = new pg.Pool({ host: 'fake-no-network', stream: () => new ParserStream(), connectionTimeoutMillis: 1000 });
  pool.on('error', () => {});
  const run = createTransactionRunner(pool.connect.bind(pool), unavailable);

  await rejectsUnavailable(run(async () => commit()));
  await pool.end();
});

test('acquisition callback errors and synchronous connect throws are unavailable', async () => {
  await rejectsUnavailable(createTransactionRunner((callback) => callback(new Error('connect failed')), unavailable)(async () => commit()));
  await rejectsUnavailable(createTransactionRunner(() => { throw new Error('connect threw'); }, unavailable)(async () => commit()));
});

test('an observer setup fault destroys the just-acquired client', async () => {
  let released;
  const client = {
    query() { return Promise.resolve({ rows: [], rowCount: 1 }); },
    release(error) { released = error; },
    on() { throw new Error('listener setup failed'); },
    removeListener() {},
  };

  await rejectsUnavailable(createTransactionRunner((callback) => callback(undefined, client), unavailable)(async () => commit()));

  assert.equal(released?.message, 'temporarily_unavailable');
});

test('checked-out error during an active query fails closed and destroys without rollback', async () => {
  const client = new Client({ faultAt: "SET LOCAL synchronous_commit = on; SET LOCAL lock_timeout = '1000ms'; SET LOCAL statement_timeout = '3000ms'; SET LOCAL idle_in_transaction_session_timeout = '5000ms'" });
  let hostErrors = 0;
  client.on('error', () => { hostErrors += 1; });

  await rejectsUnavailable(transactionFor(client)(async () => commit()));

  assert.equal(client.queries.includes('ROLLBACK'), false);
  assert.equal(client.releases.length, 1);
  assert.equal(client.releases[0]?.message, 'temporarily_unavailable');
  assert.equal(hostErrors, 1);
  assert.equal(client.listenerCount('error'), 1);
});

test('checked-out error between queries prevents COMMIT and destroys without rollback', async () => {
  const client = new Client();
  client.on('error', () => {});

  await rejectsUnavailable(transactionFor(client)(async () => {
    client.emit('error', new Error('socket lost'));
    return commit();
  }));

  assert.equal(client.queries.includes('COMMIT'), false);
  assert.equal(client.queries.includes('ROLLBACK'), false);
  assert.equal(client.releases[0]?.message, 'temporarily_unavailable');
  assert.equal(client.listenerCount('error'), 1);
});

test('checked-out error during COMMIT never runs post-commit or returns success', async () => {
  const client = new Client({ faultAt: 'COMMIT' });
  client.on('error', () => {});
  let postCommit = false;

  await rejectsUnavailable(transactionFor(client)(async () => ({ ...commit(), postCommit: () => { postCommit = true; } })));

  assert.equal(postCommit, false);
  assert.equal(client.queries.includes('ROLLBACK'), false);
  assert.equal(client.releases[0]?.message, 'temporarily_unavailable');
  assert.equal(client.listenerCount('error'), 1);
});

test('checked-out error during post-commit never returns success and destroys the client', async () => {
  const client = new Client();
  client.on('error', () => {});

  await rejectsUnavailable(transactionFor(client)(async () => ({ ...commit(), postCommit: () => {
    client.emit('error', new Error('socket lost'));
  } })));

  assert.equal(client.queries.includes('COMMIT'), true);
  assert.equal(client.queries.includes('ROLLBACK'), false);
  assert.equal(client.releases[0]?.message, 'temporarily_unavailable');
  assert.equal(client.listenerCount('error'), 1);
});

test('healthy checked-out client preserves host listener and removes runner listener on reuse', async () => {
  const client = new Client();
  let hostErrors = 0;
  client.on('error', () => { hostErrors += 1; });
  const transaction = transactionFor(client);

  assert.equal(await transaction(async () => commit()), 'value');
  assert.equal(await transaction(async () => commit()), 'value');

  assert.equal(client.releases.length, 2);
  assert.deepEqual(client.releases, [undefined, undefined]);
  assert.equal(client.listenerCount('error'), 1);
  assert.equal(hostErrors, 0);
});
