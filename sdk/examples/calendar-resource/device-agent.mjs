#!/usr/bin/env node
import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign as nodeSign, createHash } from 'node:crypto';
import { readFile, mkdir, open, rename, chmod, lstat, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { unlinkSync, lstatSync } from 'node:fs';
import https from 'node:https';

import { createAgentClient, createAgentKey } from '@atum/agent';
import { createProtectedRequestSigner } from '@atum/agent/resource-proof';
import { actionHash, canonicalAction, canonicalContext, validateBoundIntent, parseStrictJson } from '@atum/verification/context';
import { createObservedClock } from './observed-clock.mjs';

const required = name => { const value = process.env[name]; if (!value) throw new Error(`missing ${name}`); return value; };
const stateDir = required('ATUM_AGENT_STATE_DIR');
if (!stateDir.startsWith('/')) throw new Error('ATUM_AGENT_STATE_DIR must be absolute');
const statePath = join(stateDir, 'agent-state.json'); const lockPath = join(stateDir, '.lock');
async function acquireLock() { await mkdir(stateDir, { recursive: true, mode: 0o700 }); const stat = await lstat(stateDir); if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('unsafe state directory'); await chmod(stateDir, 0o700); return open(lockPath, 'wx', 0o600); }
async function loadState() { try { const named = await lstat(statePath); if (!named.isFile() || named.isSymbolicLink()) throw new Error('unsafe agent state'); const handle = await open(statePath, 'r'); try { const stat = await handle.stat(); if (!stat.isFile() || (stat.mode & 0o077)) throw new Error('unsafe agent state'); return JSON.parse(await handle.readFile('utf8')); } finally { await handle.close(); } } catch (e) { if (e.code === 'ENOENT') return null; throw e; } }
async function saveState(value) { const temp = join(stateDir, `.state-${randomBytes(12).toString('hex')}`); const handle = await open(temp, 'wx', 0o600); try { await handle.writeFile(`${JSON.stringify(value)}\n`); await handle.sync(); } finally { await handle.close(); } await rename(temp, statePath); const dir = await open(dirname(statePath), 'r'); try { await dir.sync(); } finally { await dir.close(); } }
const command = process.argv[2] ?? 'authorize';
if (!['authorize','refresh','invoke','status'].includes(command) || (command === 'invoke' && (process.argv.length !== 4 || !/^[A-Za-z0-9._:-]{1,128}$/.test(process.argv[3]))) || (command !== 'invoke' && process.argv.length !== 3)) throw new Error('usage: device-agent.mjs authorize|refresh|status|invoke <operation-label>');
let lock; try { lock = await acquireLock(); } catch { throw new Error('another Agent process owns this state directory'); }
const lockIdentity = await lock.stat();
const ownsLock = stat => stat.isFile() && !stat.isSymbolicLink() && stat.dev === lockIdentity.dev && stat.ino === lockIdentity.ino;
const exitCleanup = () => { try { if (ownsLock(lstatSync(lockPath))) unlinkSync(lockPath); } catch {} };
process.once('exit', exitCleanup);
async function releaseLock() { if (!lock) return; const owned = lock; lock = undefined; process.removeListener('exit', exitCleanup); try { await owned.close(); } finally { try { const stat = await lstat(lockPath); if (ownsLock(stat)) await unlink(lockPath); } catch (error) { if (error.code !== 'ENOENT') throw error; } } }
const exact = (value, fields) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).length === fields.length
  && fields.every(field => Object.hasOwn(value, field));
const DENIALS = new Set(['grant_not_active','grant_expired','account_not_bound','action_not_permitted','parameter_limit','evidence_insufficient','grant_limit_exhausted','authorization_expired']);
function calendarResult(value) {
  if (!exact(value, ['permission_checked','resource_acceptance','result']) || value.permission_checked !== true
      || !['accepted','replayed'].includes(value.resource_acceptance) || !exact(value.result, ['events']) || !Array.isArray(value.result.events) || value.result.events.length > 100
      || !value.result.events.every(item => exact(item, ['event_id','title','starts_at_ms']) && typeof item.event_id === 'string' && typeof item.title === 'string' && (typeof item.starts_at_ms === 'string' || Number.isSafeInteger(item.starts_at_ms)))) throw new Error('invalid calendar response');
  return value;
}

function post(material, ca) {
  const url = new URL(material.url); const body = Buffer.from(material.body, 'utf8');
  return new Promise((resolve, reject) => {
    let timer;
    const finish = (error, value) => { clearTimeout(timer); if (error) reject(error); else resolve(value); };
    const request = https.request(url, { method: material.method, ...(ca === undefined ? {} : { ca }), servername: url.hostname,
      headers: { host: url.host, authorization: material.authorization, dpop: material.dpop,
        'content-type': 'application/json', 'content-length': String(body.length) } }, response => {
      const chunks = []; let size = 0;
      response.once('error', error => finish(error));
      response.once('aborted', () => finish(new Error('resource response interrupted')));
      response.on('data', chunk => { size += chunk.length; if (size > 65_536) request.destroy(new Error('resource response too large')); else chunks.push(chunk); });
      response.on('end', () => {
        try {
          const length = response.headers['content-length'];
          if (response.headers.location || response.headers['transfer-encoding'] || !/^(?:0|[1-9][0-9]*)$/.test(length ?? '')) throw new Error('invalid resource response');
          const bytes = Buffer.concat(chunks); if (Number(length) !== bytes.length) throw new Error('invalid resource response');
          finish(null, { status: response.statusCode, headers: response.headers, body: parseStrictJson(bytes, 65_536) });
        } catch (error) { finish(error); }
      });
    });
    timer = setTimeout(() => request.destroy(new Error('resource request timed out')), 5_000);
    request.once('error', error => finish(error)); request.end(body);
  });
}

function validateSavedOperation(old, state, association, endpoint, desiredAction, registration, descriptor) {
  const publicJwk = createPublicKey(createPrivateKey({ key: state.private_jwk, format: 'jwk' })).export({ format: 'jwk' });
  const thumbprint = createHash('sha256').update(JSON.stringify({ crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x, y: publicJwk.y })).digest('base64url');
  validateBoundIntent(old.context, old.action_request, registration, descriptor);
  if (old.association !== association || JSON.stringify(old.endpoint) !== JSON.stringify(endpoint)
      || canonicalAction(old.action_request, descriptor) !== canonicalAction(desiredAction, descriptor)
      || old.operation_id !== old.context.operation_id || old.key_thumbprint !== thumbprint
      || old.context.agent_key_thumbprint !== thumbprint
      || !/^[A-Za-z0-9_-]{43}$/.test(old.token_fingerprint ?? '')
      || old.raw_body !== `{"context":${canonicalContext(old.context, descriptor)},"action_request":${canonicalAction(old.action_request, descriptor)}}`
      || !['attempting','complete','denied'].includes(old.state)
      || (old.state === 'denied' && !DENIALS.has(old.code))) throw new Error('saved operation is corrupt or belongs to another context');
  if (old.state === 'complete') calendarResult(old.result);
}

function tokenPayload(token) {
  if (typeof token !== 'string' || token.length > 16_384) throw new Error('invalid access token');
  const parts = token.split('.'); if (parts.length !== 3) throw new Error('invalid access token');
  const value = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  if (!value || typeof value !== 'object' || Array.isArray(value) || !value.atum || !value.cnf) throw new Error('invalid access token');
  return value;
}

const agentConfiguration = parseStrictJson(await readFile(required('ATUM_AGENT_CONFIG_FILE')), 65_536);
if (!exact(agentConfiguration, ['registry', 'resource_endpoint'])
    || !exact(agentConfiguration.resource_endpoint, ['method', 'url'])
    || agentConfiguration.resource_endpoint.method !== 'POST') throw new Error('invalid public Agent configuration');
const issuerCa = process.env.ATUM_ISSUER_CA_FILE ? await readFile(process.env.ATUM_ISSUER_CA_FILE, 'utf8') : undefined;
const resourceCa = process.env.ATUM_CALENDAR_CA_FILE ? await readFile(process.env.ATUM_CALENDAR_CA_FILE, 'utf8') : undefined;
const clock = createObservedClock(required('ATUM_CLOCK_OBSERVATION_FILE'), {
  maxAgeMs: Number(process.env.ATUM_CLOCK_MAX_AGE_MS ?? '1000') });
const registry = agentConfiguration.registry; const descriptor = registry?.descriptor;
if (!exact(registry, ['registration', 'descriptor', 'clients']) || !Array.isArray(registry.clients)) throw new Error('invalid service registration');
const client = registry.clients.find(value => value?.flows?.includes('device_code') && value?.permissions?.includes('calendar.event.read'));
if (!client) throw new Error('calendar Device client is not registered');
const association = createHash('sha256').update(JSON.stringify({ registration: registry.registration, descriptor, client_id: client.client_id, endpoint: agentConfiguration.resource_endpoint })).digest('base64url');
const desiredAction = { action: 'calendar.event.read', parameters: { calendar_id: process.env.ATUM_CALENDAR_ID ?? 'main', limit: Number(process.env.ATUM_CALENDAR_LIMIT ?? '10') } };
if (command === 'invoke' && (!Number.isSafeInteger(desiredAction.parameters.limit) || desiredAction.parameters.limit < 1 || desiredAction.parameters.limit > 100 || !/^[A-Za-z0-9._:-]{1,128}$/.test(desiredAction.parameters.calendar_id))) throw new Error('invalid calendar action parameters');

const state = await loadState();
if (command === 'status') { process.stdout.write(JSON.stringify({ version: 1, configured: Boolean(state), authorization: state?.authorization_state ?? 'none', refresh: state?.refresh_state ?? 'none', operations: Object.fromEntries(Object.entries(state?.operations ?? {}).map(([label, value]) => [label, value.state])) }) + '\n'); await releaseLock(); process.exit(0); }
if ((command === 'refresh' || command === 'invoke') && !state?.private_jwk) { await releaseLock(); throw new Error('no confirmed authorization; run authorize with fresh consent'); }
if ((command === 'refresh' || command === 'invoke') && state.association !== association) { await releaseLock(); throw new Error('Agent configuration, endpoint, or registration changed; obtain fresh consent'); }
if ((command === 'refresh' || command === 'invoke') && ['attempting','ambiguous'].includes(state.refresh_state)) { await releaseLock(); throw new Error('refresh outcome is unresolved; obtain fresh consent'); }
if (command === 'invoke') { const old = Object.hasOwn(state.operations ?? {}, process.argv[3]) ? state.operations[process.argv[3]] : null; if (old) { validateSavedOperation(old, state, association, agentConfiguration.resource_endpoint, desiredAction, registry.registration, descriptor); process.stdout.write(JSON.stringify(old.state === 'complete' ? { operation: process.argv[3], state: old.state, result: old.result } : { operation: process.argv[3], state: old.state, error: { code: old.code } }) + '\n'); await releaseLock(); process.exit(old.state === 'complete' ? 0 : 1); } if (state.authorization_state !== 'confirmed') { await releaseLock(); throw new Error('authorization is incomplete; obtain fresh consent'); } }
const pair = state?.private_jwk ? null : generateKeyPairSync('ec', { namedCurve: 'P-256' });
const privateJwk = state?.private_jwk ?? pair.privateKey.export({ format: 'jwk' });
const publicJwk = state?.public_jwk ?? pair.publicKey.export({ format: 'jwk' });
const privateKey = createPrivateKey({ key: privateJwk, format: 'jwk' });
const key = await createAgentKey({ publicJwk, timeoutMs: 5_000,
  sign: input => nodeSign('sha256', input, { key: privateKey, dsaEncoding: 'ieee-p1363' }) });
const issuer = registry.registration.issuer;
const agent = await createAgentClient({ registration: registry.registration, descriptor, client,
  endpoints: { options_url: `${issuer}/atum/request/options`, verify_url: `${issuer}/atum/request/verify`,
    par_url: `${issuer}/request`, authorization_url: `${issuer}/auth`,
    device_authorization_url: `${issuer}/device/auth`, token_url: `${issuer}/token` },
  tls: issuerCa === undefined ? {} : { ca: issuerCa }, key, clock, timeoutMs: 5_000, maxConcurrent: 2 });
try {
  if (command === 'refresh') {
    if (!state.refresh_token || !state.authorization_details) throw new Error('refresh is incomplete; obtain fresh consent');
    await saveState({ ...state, refresh_state: 'attempting' });
    let refreshed;
    try { refreshed = await agent.refresh({ refresh_token: state.refresh_token, authorization_details: state.authorization_details }); }
    catch (error) { await saveState({ ...state, refresh_state: 'ambiguous' }); throw error; }
    await saveState({ ...state, refresh_state: 'confirmed', access_token: refreshed.access_token, refresh_token: refreshed.refresh_token ?? state.refresh_token,
      authorization_details: refreshed.authorization_details ?? state.authorization_details });
    process.stdout.write('Agent refresh confirmed.\n');
    await agent.close(); await releaseLock(); process.exit(0);
  }
  let token; let authorizationDetails;
  if (command === 'authorize') {
    const sample = clock(); if (sample.healthy !== true) throw new Error('observed clock is unhealthy');
    const lifetime = Math.min(client.max_grant_lifetime_ms, 240_000);
    const request = { permissions: [{ action: 'calendar.event.read' }], grant_limit: Math.min(client.max_grant_limit, 2), grant_expires_at_ms: sample.now_ms + lifetime };
    await saveState({ version: 1, private_jwk: privateJwk, public_jwk: publicJwk, issuer, client_id: client.client_id,
      registration: registry.registration, descriptor, endpoint: agentConfiguration.resource_endpoint, association,
      authorization_state: 'incomplete', refresh_state: 'none', operations: state?.operations ?? {} });
    const flow = await agent.beginDeviceAuthorization(request);
    process.stdout.write(`Open ${flow.verification_uri} and enter ${flow.user_code}.\n`);
    const controller = new AbortController(); process.once('SIGINT', () => controller.abort());
    token = await flow.poll({ signal: controller.signal });
  } else { token = { access_token: state.access_token }; authorizationDetails = state.authorization_details; }
  const payload = tokenPayload(token.access_token); const claims = payload.atum;
  if (payload.iss !== issuer || payload.aud !== registry.registration.audience || payload.client_id !== client.client_id
      || typeof payload.sub !== 'string' || payload.cnf.jkt !== key.thumbprint) throw new Error('access token context mismatch');
  if (command === 'authorize') { await saveState({ version: 1, private_jwk: privateJwk, public_jwk: publicJwk, issuer, client_id: client.client_id,
      registration: registry.registration, descriptor, endpoint: agentConfiguration.resource_endpoint, association,
      authorization_state: 'confirmed', refresh_state: 'confirmed', access_token: token.access_token, refresh_token: token.refresh_token ?? null,
      authorization_details: token.authorization_details, operations: state?.operations ?? {} });
    process.stdout.write('Agent authorization confirmed. Use a new invoke operation label to request a resource action.\n'); }
  if (command !== 'authorize') {
  const actionRequest = desiredAction;
  const context = { protocol_version: '0.1.0-draft.2', resource_profile_version: claims.resource_profile_version,
    resource_profile_hash: claims.resource_profile_hash, issuer: payload.iss, audience: payload.aud,
    environment: claims.environment, tenant_id: claims.tenant_id, resource_id: claims.resource_id,
    quota_scope_id: claims.quota_scope_id, operation_namespace: claims.operation_namespace,
    scoped_subject: payload.sub, operation_id: randomBytes(32).toString('base64url'), grant_id: claims.grant_id,
    grant_version: claims.grant_version, policy_version: claims.policy_version, agent_key_thumbprint: payload.cnf.jkt,
    consent_hash: claims.consent_hash, action_hash: actionHash(actionRequest, descriptor),
    account_binding_id: claims.account_binding_id, account_binding_version: claims.account_binding_version,
    action: actionRequest.action };
  const endpoint = agentConfiguration.resource_endpoint;
  const rawBody = `{"context":${canonicalContext(context, descriptor)},"action_request":${canonicalAction(actionRequest, descriptor)}}`;
  const operation = { state: 'attempting', association, operation_id: context.operation_id, endpoint, action_request: actionRequest, context,
    raw_body: rawBody, token_fingerprint: createHash('sha256').update(token.access_token, 'ascii').digest('base64url'), key_thumbprint: key.thumbprint };
  await saveState({ ...state, authorization_state: 'confirmed', operations: { ...(state?.operations ?? {}), [process.argv[3]]: operation } });
  let signer = createProtectedRequestSigner({ key, registration: registry.registration, descriptor, endpoint, clock, timeoutMs: 5_000 });
  const input = { access_token: token.access_token, context, action_request: actionRequest };
  const challengeMaterial = await signer.signChallenge(input); if (challengeMaterial.body !== rawBody) throw new Error('signer body mismatch');
  const challenge = await post(challengeMaterial, resourceCa);
  const nonce = challenge.headers['dpop-nonce'];
  if (challenge.status !== 401 || !exact(challenge.body, ['error']) || challenge.body.error !== 'use_dpop_nonce'
      || typeof nonce !== 'string') throw new Error('resource nonce challenge rejected');
  signer = createProtectedRequestSigner({ key, registration: registry.registration, descriptor, endpoint, clock, timeoutMs: 5_000 });
  const responseMaterial = await signer.sign({ ...input, nonce }); if (responseMaterial.body !== rawBody) throw new Error('signer body mismatch');
  const response = await post(responseMaterial, resourceCa);
  if (response.status !== 200) { const code = response.body?.error?.code; if (!DENIALS.has(code)) throw new Error('calendar operation outcome unresolved'); await saveState({ ...state, authorization_state: 'confirmed', operations: { ...(state?.operations ?? {}), [process.argv[3]]: { ...operation, state: 'denied', code } } }); process.stdout.write(JSON.stringify({ error: { code } }) + '\n'); await agent.close(); await releaseLock(); process.exit(1); }
  const result = calendarResult(response.body);
  await saveState({ ...state, authorization_state: 'confirmed', operations: { ...(state?.operations ?? {}), [process.argv[3]]: { ...operation, state: 'complete', result } } });
  process.stdout.write(`${JSON.stringify(result)}\n`);
  }
} catch {
  process.exitCode = 1;
  process.stderr.write('ATUM authorization or operation was not confirmed. Do not resubmit an attempted operation automatically.\n');
} finally { await agent.close(); await releaseLock(); }
