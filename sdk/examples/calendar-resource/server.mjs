#!/usr/bin/env node
import https from 'node:https';
import { readFile, writeFile } from 'node:fs/promises';
import { createPostgresReplayStore } from '@atum/replay-postgres';
import { migratePostgresReplaySchema } from '@atum/replay-postgres/migrate';
import pg from 'pg';
import { createCalendarResource } from './resource.mjs';
import { initializeUsageSchema } from './usage-store.mjs';
import { createObservedClock } from './observed-clock.mjs';

const required = name => { const value = process.env[name]; if (!value) throw new Error(`missing ${name}`); return value; };
function getJson(url, { ca, authorization = null }) {
  url = new URL(url);
  return new Promise((resolve, reject) => {
    const request = https.request(url, { method: 'GET', ...(ca === undefined ? {} : { ca }), servername: url.hostname,
      headers: authorization === null ? {} : { authorization } }, response => {
      const chunks = []; let size = 0;
      response.on('data', chunk => { size += chunk.length; if (size > 65536) request.destroy(new Error('registry response too large')); else chunks.push(chunk); });
      response.on('end', () => {
        try {
          if (response.statusCode !== 200 || response.headers.location) throw new Error('trusted configuration request rejected');
          const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid trusted JSON response');
          resolve(value);
        } catch (error) { reject(error); }
      });
    });
    request.setTimeout(5000, () => request.destroy(new Error('registry request timed out')));
    request.on('error', reject); request.end();
  });
}

function verificationKeys(jwks) {
  if (!Array.isArray(jwks?.keys) || !jwks.keys.length || jwks.keys.length > 16) throw new Error('issuer JWKS is invalid');
  const required = ['kty','n','e','kid','alg','use']; const allowed = new Set([...required,'key_ops']);
  return jwks.keys.map(key => {
    if (key === null || typeof key !== 'object' || Array.isArray(key)
        || Object.keys(key).some(field => !allowed.has(field)) || required.some(field => !Object.hasOwn(key, field))
        || Object.hasOwn(key, 'key_ops') && (!Array.isArray(key.key_ops) || key.key_ops.length !== 1
          || !['sign','verify'].includes(key.key_ops[0]))) throw new Error('issuer JWKS is invalid');
    return Object.fromEntries(required.map(field => [field,key[field]]));
  });
}

const serviceAccessUrl = required('ATUM_SERVICE_ACCESS_URL');
const credential = required('ATUM_SERVICE_CREDENTIAL');
const serviceCa = process.env.ATUM_SERVICE_ACCESS_CA_FILE ? await readFile(process.env.ATUM_SERVICE_ACCESS_CA_FILE, 'utf8') : undefined;
const configuration = await getJson(new URL('/v1/service/registration', serviceAccessUrl),
  { ca: serviceCa, authorization: `Bearer ${credential}` });
const registry = configuration.registry;
if (configuration?.verification?.issuer_jwks_url !== `${registry?.registration?.issuer}/jwks`
    || !configuration.verification.authority_keys) throw new Error('trusted verification configuration missing');
if (!registry.descriptor.actions.includes('calendar.event.read')) throw new Error('service is not registered for calendar.event.read');
const endpoint = { method: 'POST', url: required('ATUM_CALENDAR_ENDPOINT') };
const endpointUrl = new URL(endpoint.url);
const args = process.argv.slice(2);
const exportPath = args.length === 2 && args[0] === '--export-agent-config' && args[1].startsWith('/') ? args[1] : null;
if (!exportPath && (args.length > 1 || args.length === 1 && args[0] !== '--migrate')) throw new Error('invalid command');

if (exportPath) {
  await writeFile(exportPath, `${JSON.stringify({ registry, resource_endpoint: endpoint })}\n`, { flag: 'wx', mode: 0o600 });
  process.stdout.write('public Agent configuration written\n');
} else {
  const clock = createObservedClock(required('ATUM_CLOCK_OBSERVATION_FILE'), {
    maxAgeMs: Number(process.env.ATUM_CLOCK_MAX_AGE_MS ?? '1000') });
  const issuerCa = process.env.ATUM_ISSUER_CA_FILE ? await readFile(process.env.ATUM_ISSUER_CA_FILE, 'utf8') : undefined;
  const jwks = await getJson(configuration.verification.issuer_jwks_url, { ca: issuerCa });
  const issuerKeys = verificationKeys(jwks);
  const pool = new pg.Pool({ connectionString: required('ATUM_CALENDAR_DATABASE_URL'), max: 8, connectionTimeoutMillis: 2000 });
  pool.on('error', () => {});
  if (args[0] === '--migrate') {
    await migratePostgresReplaySchema(pool); await initializeUsageSchema(pool);
    await pool.query(`CREATE TABLE IF NOT EXISTS calendar_events (
      scoped_subject text NOT NULL, calendar_id text NOT NULL, event_id text NOT NULL,
      title text NOT NULL, starts_at_ms bigint NOT NULL,
      PRIMARY KEY (scoped_subject,calendar_id,event_id))`);
    await pool.end(); process.stdout.write('calendar resource schema ready\n');
  } else {
    const replayStore = createPostgresReplayStore({ pool, clock, binding: {
      issuer: registry.registration.issuer, audience: registry.registration.audience, endpoint_url: endpoint.url } });
    const resource = await createCalendarResource({ pool, endpoint, authorization: {
      registration: registry.registration, descriptor: registry.descriptor, clock,
      proof: { issuerKeys, endpoint, replayStore },
      authority: { issuerKeys: configuration.verification.authority_keys,
        evidencePolicy: configuration.verification.evidence_policy,
        baseUrl: serviceAccessUrl, https: serviceCa === undefined ? {} : { ca: serviceCa }, serviceCredential: credential,
        timeoutMs: 5000, maxConcurrent: 4 } } });
    const server = https.createServer({ key: await readFile(required('ATUM_CALENDAR_TLS_KEY_FILE')),
      cert: await readFile(required('ATUM_CALENDAR_TLS_CERT_FILE')), minVersion: 'TLSv1.2' }, resource.handle);
    server.on('clientError', (_error, socket) => socket.destroy());
    const close = async signal => {
      server.close(); await Promise.race([new Promise(resolve => server.once('close', resolve)), new Promise(resolve => setTimeout(resolve, 5000))]);
      await resource.close(); await pool.end(); process.stdout.write(`calendar resource stopped (${signal})\n`);
    };
    process.once('SIGINT', () => close('SIGINT').finally(() => process.exit(0)));
    process.once('SIGTERM', () => close('SIGTERM').finally(() => process.exit(0)));
    const listenHost = process.env.ATUM_CALENDAR_LISTEN_HOST ?? '127.0.0.1';
    const listenPort = Number(process.env.ATUM_CALENDAR_LISTEN_PORT ?? '8443');
    if (!Number.isSafeInteger(listenPort) || listenPort < 1 || listenPort > 65535) throw new Error('invalid ATUM_CALENDAR_LISTEN_PORT');
    server.listen(listenPort, listenHost, () => process.stdout.write(`calendar resource listening on https://${listenHost}:${listenPort} for ${endpointUrl.origin}\n`));
  }
}
