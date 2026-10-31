const QUERY_TIMEOUT = Symbol('query timeout');

function remaining(unavailable, deadlineAt, maximum) {
  if (deadlineAt === undefined) return maximum;
  const left = deadlineAt - performance.now();
  if (!(left > 0)) {
    const error = unavailable(); error[QUERY_TIMEOUT] = true; throw error;
  }
  return Math.min(maximum, left);
}

function release(client, unavailable, destroy) {
  try { client.release(destroy ? unavailable() : undefined); } catch {}
}

function acquire(connect, unavailable, deadlineAt) {
  return new Promise((resolve, reject) => {
    const wait = remaining(unavailable, deadlineAt, 1000);
    let done = false;
    const timer = setTimeout(() => {
      if (!done) { done = true; reject(unavailable()); }
    }, wait);
    const callback = (error, client) => {
      if (done) { release(client, unavailable, true); return; }
      done = true;
      clearTimeout(timer);
      try { remaining(unavailable, deadlineAt, 1000); } catch (fault) {
        release(client ?? {}, unavailable, true); reject(fault); return;
      }
      if (error || !client || typeof client.query !== 'function' || typeof client.release !== 'function'
        || typeof client.on !== 'function' || typeof client.removeListener !== 'function') {
        release(client ?? {}, unavailable, true);
        reject(unavailable());
        return;
      }
      try { resolve({ client, observer: observeClient(client, unavailable) }); } catch {
        release(client, unavailable, true);
        reject(unavailable());
      }
    };
    try { connect(callback); } catch { callback(unavailable()); }
  });
}

function observeClient(client, unavailable) {
  let fault;
  const waiting = new Set();
  const onError = () => {
    if (fault) return;
    fault = unavailable();
    for (const reject of waiting) reject(fault);
  };
  client.on('error', onError);
  return {
    fault: () => fault,
    add: (reject) => waiting.add(reject),
    delete: (reject) => waiting.delete(reject),
    stop: () => client.removeListener('error', onError),
  };
}

function query(client, sql, values, unavailable, observer, deadlineAt) {
  return new Promise((resolve, reject) => {
    const wait = remaining(unavailable, deadlineAt, 4000);
    let done = false;
    let timer;
    const settle = (callback, value) => {
      if (!done) {
        done = true;
        clearTimeout(timer);
        observer.delete(onFault);
        callback(value);
      }
    };
    const onFault = (error) => settle(reject, error);
    const fault = observer.fault();
    if (fault) { reject(fault); return; }
    observer.add(onFault);
    timer = setTimeout(() => {
      if (!done) {
        const error = unavailable();
        error[QUERY_TIMEOUT] = true;
        settle(reject, error);
      }
    }, wait);
    Promise.resolve().then(() => {
      const error = observer.fault();
      if (error) throw error;
      remaining(unavailable, deadlineAt, 4000);
      return client.query(sql, values);
    }).then((result) => {
      try { remaining(unavailable, deadlineAt, 4000); } catch (error) { settle(reject, error); return; }
      settle(resolve, result);
    }, (error) => {
      settle(reject, error?.[QUERY_TIMEOUT] ? error : unavailable());
    });
  });
}

async function rollback(query) {
  await query('ROLLBACK', []);
}

export function createTransactionRunner(connect, unavailable) {
  return async function inTransaction(operation, deadlineAt) {
    let client;
    let observer;
    let clean = true;
    let uncertain = false;
    try {
      ({ client, observer } = await acquire(connect, unavailable, deadlineAt));
      const runQuery = (sql, values = []) => query(client, sql, values, unavailable, observer, deadlineAt);
      clean = false;
      await runQuery('BEGIN ISOLATION LEVEL READ COMMITTED');
      await runQuery("SET LOCAL synchronous_commit = on; SET LOCAL lock_timeout = '1000ms'; SET LOCAL statement_timeout = '3000ms'; SET LOCAL idle_in_transaction_session_timeout = '5000ms'");
      const outcome = await operation(runQuery);
      remaining(unavailable, deadlineAt, 4000);
      if (observer.fault()) throw observer.fault();
      if (outcome.commit !== true) {
        await rollback(runQuery);
        if (observer.fault()) throw observer.fault();
        clean = true;
        return outcome.value;
      }
      await runQuery('COMMIT');
      if (observer.fault()) throw observer.fault();
      clean = true;
      if (outcome.postCommit) await outcome.postCommit();
      remaining(unavailable, deadlineAt, 4000);
      if (observer.fault()) throw observer.fault();
      return outcome.value;
    } catch (error) {
      uncertain = true;
      // A timed-out command can still occupy node-postgres' query queue. Destroy now;
      // enqueueing ROLLBACK would delay release behind that unknown command.
      if (client && !clean && !error?.[QUERY_TIMEOUT] && !observer?.fault()) {
        try { await rollback((sql, values) => query(client, sql, values, unavailable, observer, deadlineAt)); clean = true; } catch {}
      }
      throw unavailable();
    } finally {
      if (client) {
        release(client, unavailable, !clean || uncertain || !!observer?.fault());
        observer?.stop();
      }
    }
  };
}
