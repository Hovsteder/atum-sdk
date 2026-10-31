import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK, SignJWT, CompactSign } from 'jose';
import { actionHash, intentHash } from '../src/context.mjs';

const modulePromise = import('../src/authority.mjs').catch(() => null);
const NOW = 1700000000123;
const HASH = 'sha256:dc6f6409a47da2a97ea7b4ace313985d7fcd4c6b8459a59ea06b014de304a175';
const action = { action: 'sandbox.execute', parameters: { resource: 'ENERGY', amount: 100, duration: 60, max_price_sun: 500 } };
const registration = { issuer: 'atum', audience: 'merx', environment: 'sandbox', tenant_id: 'tenant', resource_id: 'resource', quota_scope_id: 'scope', operation_namespace: 'operations', resource_profile_version: 'v1-draft.1', resource_profile_hash: HASH, policy_version: 'policy-v1', account_required_actions: ['prices.read', 'order.preview', 'sandbox.execute'] };
const context = { protocol_version: '0.1.0-draft.2', ...Object.fromEntries(Object.entries(registration).filter(([k]) => k !== 'account_required_actions')), scoped_subject: 'subject', operation_id: 'operation-1', grant_id: 'grant-1', grant_version: 1, agent_key_thumbprint: Buffer.alloc(32, 1).toString('base64url'), consent_hash: `sha256:${'a'.repeat(64)}`, account_binding_id: 'binding-1', account_binding_version: 1, action: action.action, action_hash: actionHash(action) };
const template = Object.fromEntries(Object.entries(context).filter(([k]) => !['operation_id', 'action', 'action_hash'].includes(k)));
const policy = { profile: 'consistency-v1', policy_version: 'policy-v1', source_profiles: ['lab-v1'], max_age_ms: 60000 };
const evidence = { assertion_id: 'evidence-1', profile: 'consistency-v1', policy_version: 'policy-v1', source_profile: 'lab-v1', evaluation_mode: 'synthetic', result: 'passed', observed_at_ms: NOW - 2000, evaluated_at_ms: NOW - 1500, issued_at_ms: NOW - 1000, valid_until_ms: NOW + 20000 };

async function fixture(options = {}) {
  const mod = await modulePromise;
  assert.equal(typeof mod?.createAuthorityVerifier, 'function', 'authority verifier must exist');
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const jwk = await exportJWK(publicKey);
  let now = NOW; let healthy = true; let uncertainty = 0;
  const config = { registration: structuredClone(registration), evidencePolicy: options.required ? structuredClone(policy) : null, issuerKeys: { 'authority-key': jwk }, clock: () => ({ now_ms: now, uncertainty_ms: uncertainty, healthy }) };
  const verifier = await mod.createAuthorityVerifier(config);
  const grant = { template: structuredClone(template), client_id: 'client-1', grant_expires_at_ms: NOW + 100000, grant_limit: 5, permissions: [{ action: 'sandbox.execute', max_amount: 1000, max_duration: 3600, max_price_sun: 1000 }] };
  const snapshot = { grant, status: 'active', evidence: options.required ? structuredClone(evidence) : null, issued_at_ms: NOW, valid_until_ms: NOW + (options.required ? 20000 : 30000) };
  const decision = { context: structuredClone(context), intent_hash: intentHash(context), admission_id: 'permit-1', decision: 'admitted', reason: 'admitted', evaluated_at_ms: NOW, evaluated_uncertainty_ms: 0, grant_expires_at_ms: NOW + 100000, acceptance_expires_at_ms: NOW + 10000, first_submit_expires_at_ms: NOW + 30000, evidence: options.required ? structuredClone(evidence) : null };
  function claims(data, kind) {
    const issued = kind === 'snapshot' ? data.issued_at_ms : data.evaluated_at_ms;
    const expires = kind === 'snapshot' ? data.valid_until_ms : data.decision === 'admitted' ? data.first_submit_expires_at_ms : issued + 300000;
    return { iss: 'atum', aud: 'merx', sub: 'subject', iat: Math.floor(issued / 1000), exp: Math.ceil(expires / 1000), jti: kind === 'snapshot' ? 'snapshot-1' : data.admission_id, profile: kind === 'snapshot' ? 'atum-grant-status-v1-draft.1' : 'atum-admission-v1-draft.1', data };
  }
  async function sign(data, kind = 'snapshot', alterClaims, alterHeader) {
    const payload = claims(data, kind); alterClaims?.(payload);
    const header = { alg: 'ES256', typ: kind === 'snapshot' ? 'atum-grant-status+jwt' : 'atum-admission+jwt', kid: 'authority-key' }; alterHeader?.(header);
    return new SignJWT(payload).setProtectedHeader(header).sign(privateKey);
  }
  return { ...mod, privateKey, config, verifier, grant, snapshot, decision, claims, sign,
    clock(value, u = 0, h = true) { now = value; uncertainty = u; healthy = h; } };
}
const bad = (code = 'invalid_proof') => error => error.code === code;

test('snapshot has trusted limits, frozen material and reservation-only effect', async () => {
  const f = await fixture();
  const result = await f.verifier.verifyGrantSnapshot(await f.sign(f.snapshot), context, action, 'client-1');
  assert.equal(result.authorization_effect, 'reservation_only');
  assert.equal(result.requires_admission, true);
  assert.equal(result.grant.grant_limit, 5);
  assert.equal(result.grant.permissions[0].max_amount, 1000);
  assert.ok(Object.isFrozen(result.grant.permissions[0]));
});

test('admission is exact-bound, immutable and has original two deadlines', async () => {
  const f = await fixture();
  const result = await f.verifier.verifyAdmission(await f.sign(f.decision, 'admission'), context, action, { mode: 'accept' });
  assert.equal(result.authorization_effect, 'admission');
  assert.equal(result.acceptance_expires_at_ms, NOW + 10000);
  assert.equal(result.first_submit_expires_at_ms, NOW + 30000);
  assert.ok(Object.isFrozen(result.context));
});

test('expired original permit can only be inspected and never re-admitted', async () => {
  const f = await fixture(); const token = await f.sign(f.decision, 'admission');
  f.clock(NOW + 400000);
  await assert.rejects(f.verifier.verifyAdmission(token, context, action, { mode: 'accept' }), bad('expired'));
  const historic = await f.verifier.verifyAdmission(token, context, action, { mode: 'inspect' });
  assert.equal(historic.authorization_effect, 'none'); assert.equal(historic.historical, true);
  assert.equal(historic.admission_id, 'permit-1');
});

test('no implicit inspect or token-only first-submit API', async () => {
  const f = await fixture(); const token = await f.sign(f.decision, 'admission');
  await assert.rejects(f.verifier.verifyAdmission(token, context, action, { mode: 'submit' }), bad('invalid_request'));
  assert.equal(f.verifier.verifyFirstSubmit, undefined);
});

for (const field of ['operation_id', 'operation_namespace', 'grant_id', 'grant_version', 'consent_hash', 'account_binding_id', 'account_binding_version', 'policy_version', 'agent_key_thumbprint']) {
  test(`admission cannot replace ${field} while retaining action`, async () => {
    const f = await fixture(); const changed = structuredClone(context);
    changed[field] = typeof changed[field] === 'number' ? changed[field] + 1 : field === 'consent_hash' ? `sha256:${'b'.repeat(64)}` : field === 'agent_key_thumbprint' ? Buffer.alloc(32, 2).toString('base64url') : `${changed[field]}-changed`;
    await assert.rejects(f.verifier.verifyAdmission(await f.sign(f.decision, 'admission'), changed, action, { mode: 'accept' }));
  });
}

test('action body and client identity cannot be substituted', async () => {
  const f = await fixture(); const token = await f.sign(f.snapshot);
  await assert.rejects(f.verifier.verifyGrantSnapshot(token, context, { ...action, parameters: { ...action.parameters, amount: 101 } }, 'client-1'));
  await assert.rejects(f.verifier.verifyGrantSnapshot(token, context, action, 'client-2'), bad());
});

for (const mutate of [d => { d.grant.grant_limit = -1; }, d => { delete d.grant.grant_limit; }, d => { d.grant.permissions[0].max_amount = null; }, d => { d.grant.permissions.push(d.grant.permissions[0]); }, d => { d.status = 'revoked'; }, d => { d.valid_until_ms += 1; }, d => { d.grant.extra = true; }]) {
  test(`malformed trusted snapshot rejected: ${mutate}`, async () => {
    const f = await fixture(); mutate(f.snapshot);
    await assert.rejects(f.verifier.verifyGrantSnapshot(await f.sign(f.snapshot), context, action, 'client-1'), bad());
  });
}

for (const mutate of [d => { d.intent_hash = d.context.action_hash; }, d => { d.acceptance_expires_at_ms += 1; }, d => { d.first_submit_expires_at_ms += 1; }, d => { d.reason = 'anything'; }, d => { d.evaluated_uncertainty_ms = 1001; }, d => { d.grant_expires_at_ms = d.evaluated_at_ms; }]) {
  test(`malformed signed admission rejected: ${mutate}`, async () => {
    const f = await fixture(); mutate(f.decision);
    await assert.rejects(f.verifier.verifyAdmission(await f.sign(f.decision, 'admission'), context, action, { mode: 'inspect' }), bad());
  });
}

test('expiry equality and measured uncertainty fail closed', async () => {
  const f = await fixture(); const token = await f.sign(f.decision, 'admission');
  f.clock(NOW + 9999, 1);
  await assert.rejects(f.verifier.verifyAdmission(token, context, action, { mode: 'accept' }), bad('expired'));
  f.clock(NOW, 0, false);
  await assert.rejects(f.verifier.verifyAdmission(token, context, action, { mode: 'accept' }), bad('temporarily_unavailable'));
});

test('same-second millisecond cap is valid but does not gain one second', async () => {
  const f = await fixture(); const expiry = NOW + 10;
  f.decision.grant_expires_at_ms = expiry; f.decision.acceptance_expires_at_ms = expiry; f.decision.first_submit_expires_at_ms = expiry;
  const token = await f.sign(f.decision, 'admission');
  assert.equal((await f.verifier.verifyAdmission(token, context, action, { mode: 'accept' })).authorization_effect, 'admission');
  f.clock(expiry);
  await assert.rejects(f.verifier.verifyAdmission(token, context, action, { mode: 'accept' }), bad('expired'));
});

test('signed denial remains denial and carries no deadlines', async () => {
  const f = await fixture(); Object.assign(f.decision, { decision: 'denied', reason: 'grant_not_active', acceptance_expires_at_ms: null, first_submit_expires_at_ms: null });
  const value = await f.verifier.verifyAdmission(await f.sign(f.decision, 'admission'), context, action, { mode: 'accept' });
  assert.equal(value.authorization_effect, 'none'); assert.equal(value.decision, 'denied');
});

test('evidence policy requires explicit current matching passed material', async () => {
  const f = await fixture({ required: true });
  assert.equal((await f.verifier.verifyGrantSnapshot(await f.sign(f.snapshot), context, action, 'client-1')).evidence.result, 'passed');
  for (const mutate of [d => { d.evidence = null; }, d => { d.evidence.result = 'failed'; }, d => { d.evidence.source_profile = 'untrusted'; }, d => { d.evidence.observed_at_ms = NOW - 60001; }, d => { d.evidence.issued_at_ms = NOW + 1; }, d => { d.evidence.evaluation_mode = 'phone_claimed'; }]) {
    const data = structuredClone(f.snapshot); mutate(data);
    await assert.rejects(f.verifier.verifyGrantSnapshot(await f.sign(data), context, action, 'client-1'), bad());
  }
});

test('wrong signature, unpinned key, role/alg, extra claims and malformed dates fail', async () => {
  const f = await fixture();
  const cases = [
    await f.sign(f.snapshot, 'snapshot', c => { c.iss = 'other'; }),
    await f.sign(f.snapshot, 'snapshot', c => { c.exp++; }),
    await f.sign(f.snapshot, 'snapshot', c => { c.iat += 0.5; }),
    await f.sign(f.snapshot, 'snapshot', c => { c.sub = 'other'; }),
    await f.sign(f.snapshot, 'snapshot', c => { c.scope = 'atum:invoke'; }),
    await f.sign(f.snapshot, 'snapshot', undefined, h => { h.kid = 'unknown'; }),
    await f.sign(f.snapshot, 'snapshot', undefined, h => { h.typ = 'at+jwt'; }),
  ];
  const other = await generateKeyPair('ES256');
  cases.push(await new SignJWT(f.claims(f.snapshot, 'snapshot')).setProtectedHeader({ alg: 'ES256', typ: 'atum-grant-status+jwt', kid: 'authority-key' }).sign(other.privateKey));
  for (const token of cases) await assert.rejects(f.verifier.verifyGrantSnapshot(token, context, action, 'client-1'), bad());
});

test('duplicate signed JSON is rejected before accepting cryptographic claims', async () => {
  const f = await fixture();
  const raw = JSON.stringify(f.claims(f.snapshot, 'snapshot')).replace('"grant_limit":5', '"grant_limit":999,"grant_limit":5');
  const token = await new CompactSign(Buffer.from(raw)).setProtectedHeader({ alg: 'ES256', typ: 'atum-grant-status+jwt', kid: 'authority-key' }).sign(f.privateKey);
  await assert.rejects(f.verifier.verifyGrantSnapshot(token, context, action, 'client-1'), bad());
});

test('configuration is copied and request context cannot mutate during verification', async () => {
  const f = await fixture(); const token = await f.sign(f.snapshot);
  f.config.registration.issuer = 'changed'; f.config.issuerKeys['authority-key'].x = 'broken';
  const input = structuredClone(context); const pending = f.verifier.verifyGrantSnapshot(token, input, action, 'client-1');
  input.grant_id = 'changed';
  assert.equal((await pending).grant.template.grant_id, 'grant-1');
});

test('required account binding applies to every grant permission, not only request action', async () => {
  const f = await fixture();
  const customRegistration = { ...registration, account_required_actions: ['sandbox.execute'] };
  const verifier = await f.createAuthorityVerifier({ ...f.config, registration: customRegistration });
  f.snapshot.grant.template.account_binding_id = null;
  f.snapshot.grant.template.account_binding_version = null;
  const read = { action: 'prices.read', parameters: {} };
  const readContext = { ...context, account_binding_id: null, account_binding_version: null, action: read.action, action_hash: actionHash(read) };
  await assert.rejects(verifier.verifyGrantSnapshot(await f.sign(f.snapshot), readContext, read, 'client-1'), bad());
});
