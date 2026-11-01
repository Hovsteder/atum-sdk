import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, writeFile, mkdir, lstat, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { actionHash, canonicalAction, canonicalContext } from '@atum/verification/context';
import { hashServiceDescriptor } from '@atum/verification/service-profile';

const descriptor = { profile: 'atum.service-actions.v1-draft.1', actions: ['calendar.event.read'], account_required_actions: [] };
const registration = { issuer: 'https://issuer.example', audience: 'https://calendar.example', environment: 'sandbox', tenant_id: 'calendar', resource_id: 'calendar', quota_scope_id: 'owner', operation_namespace: 'calendar', resource_profile_version: descriptor.profile, resource_profile_hash: hashServiceDescriptor(descriptor), policy_version: 'owner-passkey-v1', account_required_actions: [] };
const client = { client_id: 'calendar-device', flows: ['device_code'], permissions: ['calendar.event.read'], max_grant_lifetime_ms: 1000, max_grant_limit: 1 };
const endpoint = { method: 'POST', url: 'https://calendar.example/calendar/events' };
const association = createHash('sha256').update(JSON.stringify({ registration, descriptor, client_id: client.client_id, endpoint })).digest('base64url');
async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), 'atum-agent-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const state = join(dir, 'state'), config = join(dir, 'config.json'), network = join(dir, 'network.log'), preload = join(dir, 'network-guard.mjs');
  await mkdir(state, { mode: 0o700 });
  await writeFile(config, JSON.stringify({ registry: { registration, descriptor, clients: [client] }, resource_endpoint: endpoint }));
  // An explicit test-only observer makes every attempted HTTPS call observable.
  await writeFile(preload, `import https from 'node:https'; import {appendFileSync} from 'node:fs'; https.request=()=>{appendFileSync(${JSON.stringify(network)},'HTTP\\n');throw new Error('network forbidden in cached-state fixture');};`);
  const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const publicJwk = pair.publicKey.export({ format: 'jwk' });
  const thumbprint = createHash('sha256').update(JSON.stringify({ crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x, y: publicJwk.y })).digest('base64url');
  const action = { action: 'calendar.event.read', parameters: { calendar_id: 'main', limit: 10 } };
  const context = { ...registration, protocol_version: '0.1.0-draft.2', scoped_subject: 'subject', operation_id: 'original-operation', grant_id: 'original-grant', grant_version: 1, agent_key_thumbprint: thumbprint, consent_hash: `sha256:${'a'.repeat(64)}`, action: action.action, action_hash: actionHash(action, descriptor), account_binding_id: null, account_binding_version: null };
  delete context.account_required_actions;
  const op = { association, endpoint, action_request: action, context, operation_id: context.operation_id, key_thumbprint: thumbprint,
    token_fingerprint: 'a'.repeat(43), raw_body: `{"context":${canonicalContext(context,descriptor)},"action_request":${canonicalAction(action,descriptor)}}`, state: 'complete',
    result: { permission_checked: true, resource_acceptance: 'accepted', result: { events: [] } } };
  const base = { version: 1, private_jwk: pair.privateKey.export({ format: 'jwk' }), public_jwk: publicJwk, association,
    authorization_state: 'confirmed', refresh_state: 'confirmed', operations: { done: op, denied: { ...op, state: 'denied', code: 'grant_not_active' }, unknown: { ...op, state: 'attempting' } } };
  const statePath = join(state, 'agent-state.json');
  await writeFile(statePath, JSON.stringify(base), { mode: 0o600 });
  return { dir, state, config, network, preload, base, statePath };
}
function run(f, args, extraEnv = {}) {
  return spawnSync(process.execPath, ['--import', f.preload, 'device-agent.mjs', ...args], {
    cwd: new URL('.', import.meta.url).pathname, timeout: 10_000,
    env: { ...process.env, ATUM_AGENT_STATE_DIR: f.state, ATUM_AGENT_CONFIG_FILE: f.config, ATUM_CLOCK_OBSERVATION_FILE: join(f.dir, 'clock.json'), ...extraEnv }, encoding: 'utf8' });
}

test('fresh processes recover exact completed/denied/unresolved state without network and release only their own locks', async t => {
  const f = await fixture(t);
  for (const [label, status, marker] of [['done',0,'complete'],['denied',1,'grant_not_active'],['unknown',1,'attempting']]) {
    const result = run(f, ['invoke',label]); assert.equal(result.status, status, result.stderr); assert.match(result.stdout, new RegExp(marker));
    assert.equal(await lstat(join(f.state,'.lock')).catch(()=>null), null);
  }
  const original = await readFile(f.statePath,'utf8');
  assert.equal(run(f, ['invoke','done'], { ATUM_CALENDAR_LIMIT: '11' }).status, 1);
  const corrupt = structuredClone(f.base); corrupt.operations.done.raw_body = '{}';
  await writeFile(f.statePath, JSON.stringify(corrupt)); assert.equal(run(f,['invoke','done']).status,1);
  await writeFile(f.statePath, original);
  await writeFile(join(f.state,'.lock'),'another process owns this lock',{mode:0o600});
  assert.equal(run(f,['status']).status,1); assert.equal(await readFile(join(f.state,'.lock'),'utf8'),'another process owns this lock');
  assert.equal(await lstat(f.network).catch(()=>null), null);
});

test('attempted/ambiguous refresh and changed registration never reuse one-time tokens or old operation labels', async t => {
  const f = await fixture(t);
  for (const refresh_state of ['attempting','ambiguous']) {
    await writeFile(f.statePath,JSON.stringify({...f.base,refresh_state,refresh_token:'must-never-be-used'}));
    for (const args of [['refresh'],['invoke','new-operation']]) {
      const result=run(f,args); assert.equal(result.status,1); assert.match(result.stderr,/refresh outcome is unresolved/);
      assert.equal(await lstat(join(f.state,'.lock')).catch(()=>null),null);
    }
  }
  await writeFile(f.statePath,JSON.stringify({...f.base,association:'changed-registration'}));
  assert.equal(run(f,['invoke','done']).status,1);
  assert.equal(await lstat(f.network).catch(()=>null),null);
});
