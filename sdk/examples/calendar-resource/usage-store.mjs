/** Example resource-owned durable acceptance. It is deliberately separate from ATUM verification. */
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const MAX_TIME = 8_640_000_000_000_000;
const exact = (value, fields) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).length === fields.length
  && fields.every(field => Object.hasOwn(value, field));
const integer = (value, lower = 0, upper = MAX_SAFE) => typeof value === 'number'
  && Number.isSafeInteger(value) && !Object.is(value, -0) && value >= lower && value <= upper;

export class UsageError extends Error {
  constructor(code) { super(code); this.name = 'UsageError'; this.code = code; }
}

function canonicalJson(value, depth = 0) {
  if (depth > 12) throw new UsageError('invalid_request');
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!integer(value, -MAX_SAFE, MAX_SAFE)) throw new UsageError('invalid_request');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(item => canonicalJson(item, depth + 1)).join(',')}]`;
  if (value === null || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) throw new UsageError('invalid_request');
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key], depth + 1)}`).join(',')}}`;
}

function observed(clock) {
  let value;
  try { value = clock(); } catch { throw new UsageError('temporarily_unavailable'); }
  if (!exact(value, ['now_ms', 'uncertainty_ms', 'healthy']) || value.healthy !== true
      || !integer(value.now_ms, 0, MAX_TIME) || !integer(value.uncertainty_ms, 0, 1_000)) {
    throw new UsageError('temporarily_unavailable');
  }
  return value;
}

function remainingMs(authorization, clock, maximum) {
  const sample = observed(clock);
  const upperNow = sample.now_ms + sample.uncertainty_ms;
  const cap = Math.min(authorization.token_expires_at_ms, authorization.grant_expires_at_ms,
    authorization.snapshot_valid_until_ms, authorization.acceptance_expires_at_ms,
    authorization.first_submit_expires_at_ms);
  const remaining = cap - upperNow;
  if (remaining <= 0) throw new UsageError('authorization_expired');
  return { sample, timeout: Math.max(1, Math.min(maximum, remaining - 1)) };
}

async function boundedConnection(pool, timeout) {
  let timer; let timedOut = false;
  const pending = pool.connect();
  const expiration = new Promise((resolve, reject) => {
    timer = setTimeout(() => { timedOut = true; reject(new UsageError('temporarily_unavailable')); }, timeout);
  });
  try { return await Promise.race([pending, expiration]); }
  catch (error) {
    if (timedOut) pending.then(client => client.release()).catch(() => {});
    throw error;
  } finally { clearTimeout(timer); }
}

export async function initializeUsageSchema(pool) {
  await pool.query(`CREATE TABLE IF NOT EXISTS atum_example_calendar_usage (
    grant_scope_json text NOT NULL,
    operation_id text NOT NULL,
    context_json text NOT NULL,
    admission_id text NOT NULL UNIQUE,
    intent_hash text NOT NULL,
    client_id text NOT NULL,
    action_json text NOT NULL,
    permissions_json text NOT NULL,
    grant_limit integer NOT NULL CHECK (grant_limit BETWEEN 0 AND 1000000000),
    token_expires_at_ms bigint NOT NULL,
    grant_expires_at_ms bigint NOT NULL,
    snapshot_valid_until_ms bigint NOT NULL,
    acceptance_expires_at_ms bigint NOT NULL,
    first_submit_expires_at_ms bigint NOT NULL,
    result_json text NOT NULL,
    accepted_at_ms bigint NOT NULL,
    accepted_uncertainty_ms bigint NOT NULL,
    PRIMARY KEY (grant_scope_json, operation_id)
  )`);
}

export function createUsageStore(pool, { clock, maxWaitMs = 1_000 }) {
  if (!pool || typeof pool.connect !== 'function' || typeof clock !== 'function'
      || !integer(maxWaitMs, 1, 5_000)) throw new TypeError('invalid usage store config');
  return Object.freeze({ async acceptAndRun(authorization, operation) {
    const fields = ['context', 'admission_id', 'intent_hash', 'client_id', 'action_request', 'permissions', 'grant_limit',
      'token_expires_at_ms', 'grant_expires_at_ms', 'snapshot_valid_until_ms', 'acceptance_expires_at_ms',
      'first_submit_expires_at_ms'];
    if (!exact(authorization, fields) || typeof operation !== 'function'
        || !integer(authorization.grant_limit, 0, 1_000_000_000)
        || !Array.isArray(authorization.permissions)
        || !exact(authorization.context, ['protocol_version', 'resource_profile_version', 'resource_profile_hash', 'issuer', 'audience',
          'environment', 'tenant_id', 'resource_id', 'quota_scope_id', 'operation_namespace', 'scoped_subject', 'operation_id',
          'grant_id', 'grant_version', 'policy_version', 'agent_key_thumbprint', 'consent_hash', 'action_hash',
          'account_binding_id', 'account_binding_version', 'action'])
        || !fields.slice(7).every(field => integer(authorization[field], 1, MAX_TIME))) throw new UsageError('invalid_request');

    const contextJson = canonicalJson(authorization.context);
    const actionJson = canonicalJson(authorization.action_request);
    const permissionsJson = canonicalJson(authorization.permissions);
    const grantScope = Object.fromEntries(['issuer', 'environment', 'audience', 'tenant_id', 'resource_id',
      'quota_scope_id', 'scoped_subject', 'grant_id', 'grant_version'].map(field => [field, authorization.context[field]]));
    grantScope.client_id = authorization.client_id;
    const grantScopeJson = canonicalJson(grantScope);
    const firstWindow = remainingMs(authorization, clock, maxWaitMs);
    const client = await boundedConnection(pool, firstWindow.timeout);
    let commitCompleted = false;
    try {
      await client.query('BEGIN');
      const lockedWindow = remainingMs(authorization, clock, maxWaitMs);
      await client.query(`SET LOCAL lock_timeout = '${lockedWindow.timeout}ms'`);
      await client.query(`SET LOCAL statement_timeout = '${lockedWindow.timeout}ms'`);
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [grantScopeJson]);
      const existing = await client.query('SELECT * FROM atum_example_calendar_usage WHERE grant_scope_json=$1 AND operation_id=$2',
        [grantScopeJson, authorization.context.operation_id]);
      if (existing.rowCount === 1) {
        const row = existing.rows[0];
        if (row.context_json !== contextJson || row.intent_hash !== authorization.intent_hash
            || row.client_id !== authorization.client_id || row.action_json !== actionJson
            || row.permissions_json !== permissionsJson || Number(row.grant_limit) !== authorization.grant_limit) {
          throw new UsageError('conflict');
        }
        const replayAuthorization = { ...authorization };
        for (const field of ['token_expires_at_ms', 'grant_expires_at_ms', 'snapshot_valid_until_ms',
          'acceptance_expires_at_ms', 'first_submit_expires_at_ms']) {
          replayAuthorization[field] = Math.min(authorization[field], Number(row[field]));
        }
        const replayWindow = remainingMs(replayAuthorization, clock, maxWaitMs);
        await client.query(`SET LOCAL statement_timeout = '${replayWindow.timeout}ms'`);
        await client.query('COMMIT');
        commitCompleted = true;
        remainingMs(replayAuthorization, clock, maxWaitMs);
        return Object.freeze({ replayed: true, result: JSON.parse(row.result_json) });
      }
      const used = Number((await client.query('SELECT count(*) AS count FROM atum_example_calendar_usage WHERE grant_scope_json=$1',
        [grantScopeJson])).rows[0].count);
      if (used >= authorization.grant_limit) throw new UsageError('grant_limit_exhausted');
      const acceptance = remainingMs(authorization, clock, maxWaitMs);
      const result = await operation(client);
      const resultJson = canonicalJson(result);
      const insertWindow = remainingMs(authorization, clock, maxWaitMs);
      await client.query(`SET LOCAL statement_timeout = '${insertWindow.timeout}ms'`);
      await client.query(`INSERT INTO atum_example_calendar_usage
        (grant_scope_json,operation_id,context_json,admission_id,intent_hash,client_id,action_json,permissions_json,
         grant_limit,token_expires_at_ms,grant_expires_at_ms,snapshot_valid_until_ms,acceptance_expires_at_ms,
         first_submit_expires_at_ms,result_json,accepted_at_ms,accepted_uncertainty_ms)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
      [grantScopeJson, authorization.context.operation_id, contextJson, authorization.admission_id,
        authorization.intent_hash, authorization.client_id, actionJson, permissionsJson, authorization.grant_limit,
        authorization.token_expires_at_ms, authorization.grant_expires_at_ms, authorization.snapshot_valid_until_ms,
        authorization.acceptance_expires_at_ms, authorization.first_submit_expires_at_ms, resultJson,
        acceptance.sample.now_ms, acceptance.sample.uncertainty_ms]);
      const commitWindow = remainingMs(authorization, clock, maxWaitMs);
      await client.query(`SET LOCAL statement_timeout = '${commitWindow.timeout}ms'`);
      // A transport error from COMMIT is intentionally ambiguous. The caller receives
      // temporarily_unavailable and an exact retry recovers the row if it committed.
      await client.query('COMMIT');
      commitCompleted = true;
      try { remainingMs(authorization, clock, maxWaitMs); }
      catch { throw new UsageError('temporarily_unavailable'); }
      return Object.freeze({ replayed: false, result });
    } catch (error) {
      if (!commitCompleted) {
        try { await client.query('ROLLBACK'); } catch { /* caller receives the original failure */ }
      }
      if (error instanceof UsageError) throw error;
      throw new UsageError('temporarily_unavailable');
    } finally { client.release(); }
  } });
}
