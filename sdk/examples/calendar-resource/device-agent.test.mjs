import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, writeFile, chmod, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const root = new URL('../../..', import.meta.url).pathname;
const descriptor = { profile: 'atum.service-actions.v1-draft.1', actions: ['calendar.event.read'], account_required_actions: [] };
const registration = { issuer: 'https://issuer.example', audience: 'https://calendar.example', environment: 'sandbox', tenant_id: 'calendar', resource_id: 'calendar', quota_scope_id: 'owner', operation_namespace: 'calendar', resource_profile_version: descriptor.profile, resource_profile_hash: 'sha256:placeholder', policy_version: 'owner-passkey-v1', account_required_actions: [] };
const client = { client_id: 'calendar-device', flows: ['device_code'], permissions: ['calendar.event.read'], max_grant_lifetime_ms: 1000, max_grant_limit: 1 };
const endpoint = { method: 'POST', url: 'https://calendar.example/calendar/events' };
const association = createHash('sha256').update(JSON.stringify({ registration, descriptor, client_id: client.client_id, endpoint })).digest('base64url');
async function fixture() { const dir = await mkdtemp(join(tmpdir(), 'atum-agent-')); const state = join(dir, 'state'); const config = join(dir, 'config.json'); await writeFile(config, JSON.stringify({ registry: { registration, descriptor, clients: [client] }, resource_endpoint: endpoint })); return { dir, state, config }; }
function run(f, ...args) { return spawnSync(process.execPath, ['device-agent.mjs', ...args], { cwd: new URL('.', import.meta.url).pathname, env: { ...process.env, ATUM_AGENT_STATE_DIR: f.state, ATUM_AGENT_CONFIG_FILE: f.config, ATUM_CLOCK_OBSERVATION_FILE: join(f.dir, 'clock.json') }, encoding: 'utf8' }); }

test('cached completed and denied operations release their lock and never connect', async () => {
  const f = await fixture(); await (await import('node:fs/promises')).mkdir(f.state, { recursive: true, mode: 0o700 });
  const base = { private_jwk: {}, association, authorization_state: 'confirmed', refresh_state: 'confirmed', operations: {} };
  const op = { association, endpoint, action_request: { action: 'calendar.event.read', parameters: { calendar_id: 'main', limit: 10 } }, context: {}, raw_body: '{}', state: 'complete', result: { events: [] } };
  await writeFile(join(f.state, 'agent-state.json'), JSON.stringify({ ...base, operations: { done: op, denied: { ...op, state: 'denied', code: 'grant_not_active' } } }), { mode: 0o600 });
  const done = run(f, 'invoke', 'done'); assert.equal(done.status, 0); assert.match(done.stdout, /"complete"/); assert.equal((await lstat(join(f.state, '.lock')).catch(()=>null)), null);
  const denied = run(f, 'invoke', 'denied'); assert.equal(denied.status, 1); assert.match(denied.stdout, /grant_not_active/); assert.equal((await lstat(join(f.state, '.lock')).catch(()=>null)), null);
  const changed = run({ ...f, config: f.config }, 'invoke', 'done'); assert.equal(changed.status, 0);
});
