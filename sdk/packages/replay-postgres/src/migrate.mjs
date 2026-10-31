import { readFile } from 'node:fs/promises';

const columns = [
  ['nonces','nonce_hash','character(64)',true,'C'], ['nonces','issuer','character varying(256)',true,'C'],
  ['nonces','audience','character varying(256)',true,'C'], ['nonces','agent_key_thumbprint','character varying(43)',true,'C'],
  ['nonces','endpoint_url','character varying(2048)',true,'C'], ['nonces','issued_at_ms','bigint',true,''],
  ['nonces','expires_at_ms','bigint',true,''], ['nonces','consumed_at_ms','bigint',false,''],
  ['proofs','issuer','character varying(256)',true,'C'], ['proofs','audience','character varying(256)',true,'C'],
  ['proofs','agent_key_thumbprint','character varying(43)',true,'C'], ['proofs','proof_jti','character varying(128)',true,'C'],
  ['proofs','intent_hash','character(71)',true,'C'], ['proofs','first_seen_ms','bigint',true,''],
  ['proofs','expires_at_ms','bigint',true,''],
];
const constraints = [
  ['nonces','nonces_agent_key_thumbprint_check','c','CHECK (length(agent_key_thumbprint::text) = 43)'],
  ['nonces','nonces_audience_check','c','CHECK (length(audience::text) >= 1 AND length(audience::text) <= 256)'],
  ['nonces','nonces_check','c','CHECK (expires_at_ms > issued_at_ms)'],
  ['nonces','nonces_consumed_at_ms_check','c',"CHECK (consumed_at_ms >= 0 AND consumed_at_ms <= '8640000000000000'::bigint)"],
  ['nonces','nonces_endpoint_url_check','c','CHECK (length(endpoint_url::text) >= 1 AND length(endpoint_url::text) <= 2048)'],
  ['nonces','nonces_expires_at_ms_check','c',"CHECK (expires_at_ms >= 0 AND expires_at_ms <= '8640000000000000'::bigint)"],
  ['nonces','nonces_issued_at_ms_check','c',"CHECK (issued_at_ms >= 0 AND issued_at_ms <= '8640000000000000'::bigint)"],
  ['nonces','nonces_issuer_check','c','CHECK (length(issuer::text) >= 1 AND length(issuer::text) <= 256)'],
  ['nonces','nonces_nonce_hash_check','c',"CHECK (nonce_hash ~ '^[0-9a-f]{64}$'::text)"],
  ['nonces','nonces_pkey','p','PRIMARY KEY (nonce_hash)'],
  ['proofs','proofs_agent_key_thumbprint_check','c','CHECK (length(agent_key_thumbprint::text) = 43)'],
  ['proofs','proofs_audience_check','c','CHECK (length(audience::text) >= 1 AND length(audience::text) <= 256)'],
  ['proofs','proofs_check','c','CHECK (expires_at_ms >= first_seen_ms)'],
  ['proofs','proofs_expires_at_ms_check','c',"CHECK (expires_at_ms >= 0 AND expires_at_ms <= '8640000000000000'::bigint)"],
  ['proofs','proofs_first_seen_ms_check','c',"CHECK (first_seen_ms >= 0 AND first_seen_ms <= '8640000000000000'::bigint)"],
  ['proofs','proofs_intent_hash_check','c',"CHECK (intent_hash ~ '^sha256:[0-9a-f]{64}$'::text)"],
  ['proofs','proofs_issuer_check','c','CHECK (length(issuer::text) >= 1 AND length(issuer::text) <= 256)'],
  ['proofs','proofs_pkey','p','PRIMARY KEY (issuer, audience, agent_key_thumbprint, proof_jti)'],
  ['proofs','proofs_proof_jti_check','c','CHECK (length(proof_jti::text) >= 16 AND length(proof_jti::text) <= 128)'],
];
const v1Indexes = [
  ['nonces_expiry_idx','CREATE INDEX nonces_expiry_idx ON atum_request_proofs.nonces USING btree (expires_at_ms)'],
  ['nonces_pkey','CREATE UNIQUE INDEX nonces_pkey ON atum_request_proofs.nonces USING btree (nonce_hash)'],
  ['proofs_expiry_idx','CREATE INDEX proofs_expiry_idx ON atum_request_proofs.proofs USING btree (expires_at_ms)'],
  ['proofs_pkey','CREATE UNIQUE INDEX proofs_pkey ON atum_request_proofs.proofs USING btree (issuer, audience, agent_key_thumbprint, proof_jti)'],
];
const activeIndex = ['nonces_active_key_expiry_idx','CREATE INDEX nonces_active_key_expiry_idx ON atum_request_proofs.nonces USING btree (issuer, audience, agent_key_thumbprint, expires_at_ms) WHERE (consumed_at_ms IS NULL)'];
const relations = indexes => [['nonces','r'], ...indexes.filter(([name]) => name.startsWith('nonces')).map(([name]) => [name,'i']),
  ['proofs','r'], ...indexes.filter(([name]) => name.startsWith('proofs')).map(([name]) => [name,'i'])].sort((a,b) => a[0].localeCompare(b[0]));
const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);

async function catalog(client) {
  const present = await client.query("SELECT to_regnamespace('atum_request_proofs') IS NOT NULL AS present");
  if (!present.rows[0].present) return null;
  const relationRows = await client.query("SELECT c.relname,c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='atum_request_proofs' ORDER BY 1,2");
  const columnRows = await client.query("SELECT c.relname,a.attname,format_type(a.atttypid,a.atttypmod) AS type,a.attnotnull,coalesce(coll.collname,'') AS collation FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_collation coll ON coll.oid=a.attcollation WHERE n.nspname='atum_request_proofs' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum");
  const constraintRows = await client.query("SELECT c.relname,con.conname,con.contype,pg_get_constraintdef(con.oid,true) AS definition FROM pg_constraint con JOIN pg_class c ON c.oid=con.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='atum_request_proofs' ORDER BY c.relname,con.conname");
  const indexRows = await client.query("SELECT c.relname,pg_get_indexdef(c.oid) AS definition FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='atum_request_proofs' AND c.relkind='i' ORDER BY c.relname");
  return { relations: relationRows.rows.map(row => [row.relname,row.relkind]),
    columns: columnRows.rows.map(row => [row.relname,row.attname,row.type,row.attnotnull,row.collation]),
    constraints: constraintRows.rows.map(row => [row.relname,row.conname,row.contype,row.definition]),
    indexes: indexRows.rows.map(row => [row.relname,row.definition]) };
}

function schemaVersion(value) {
  if (!value || !same(value.columns, columns) || !same(value.constraints, constraints)) return 0;
  if (same(value.indexes, v1Indexes) && same(value.relations, relations(v1Indexes))) return 1;
  const v2Indexes = [activeIndex, ...v1Indexes].sort((a,b) => a[0].localeCompare(b[0]));
  return same(value.indexes, v2Indexes) && same(value.relations, relations(v2Indexes)) ? 2 : 0;
}

export async function migratePostgresReplaySchema(pool) {
  if (!pool || typeof pool.connect !== 'function') throw new TypeError('invalid PostgreSQL pool');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL lock_timeout = '5000ms'; SET LOCAL statement_timeout = '10000ms'");
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended('atum.replay-postgres.migrate.v1',0))");
    let installed = await catalog(client); let version = installed === null ? null : schemaVersion(installed);
    if (version === 0) throw new Error('incompatible replay schema');
    if (version === null) {
      await client.query(await readFile(new URL('../migrations/001_nonce_replay.sql', import.meta.url), 'utf8'));
      version = 1;
    }
    if (version === 1) await client.query(await readFile(new URL('../migrations/002_nonce_challenge_capacity.sql', import.meta.url), 'utf8'));
    installed = await catalog(client);
    if (schemaVersion(installed) !== 2) throw new Error('replay schema migration validation failed');
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { client.release(); }
}
