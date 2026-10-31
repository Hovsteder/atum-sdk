// Synthetic keys are generated in memory. Only public keys and signed fixtures persist.
import { writeFile } from 'node:fs/promises';
import { CompactSign, generateKeyPair, exportJWK } from 'jose';
import { actionHash, intentHash } from '../src/context.mjs';

const NOW = 1700000000123;
const registration = { issuer: 'atum.synthetic.test', audience: 'merx.synthetic.test', environment: 'sandbox', tenant_id: 'tenant.alpha', resource_id: 'resource.alpha', quota_scope_id: 'quota.main', operation_namespace: 'sandbox', resource_profile_version: 'v1-draft.1', resource_profile_hash: 'sha256:dc6f6409a47da2a97ea7b4ace313985d7fcd4c6b8459a59ea06b014de304a175', policy_version: 'policy.v1', account_required_actions: ['prices.read', 'order.preview', 'sandbox.execute'] };
const action = { action: 'sandbox.execute', parameters: { resource: 'ENERGY', amount: 100, duration: 60, max_price_sun: 500 } };
const context = { protocol_version: '0.1.0-draft.2', ...Object.fromEntries(Object.entries(registration).filter(([k]) => k !== 'account_required_actions')), scoped_subject: 'subject.alpha', operation_id: 'operation.alpha', grant_id: 'grant.alpha', grant_version: 1, agent_key_thumbprint: Buffer.alloc(32, 3).toString('base64url'), consent_hash: `sha256:${'b'.repeat(64)}`, action_hash: actionHash(action), account_binding_id: 'binding.alpha', account_binding_version: 1, action: action.action };
const template = Object.fromEntries(Object.entries(context).filter(([k]) => !['operation_id', 'action', 'action_hash'].includes(k)));
const evidence = { assertion_id: 'evidence.alpha', profile: 'consistency.v1', policy_version: 'policy.v1', source_profile: 'synthetic.lab', evaluation_mode: 'synthetic', result: 'passed', observed_at_ms: NOW - 2000, evaluated_at_ms: NOW - 1500, issued_at_ms: NOW - 1000, valid_until_ms: NOW + 20000 };
const policy = { profile: 'consistency.v1', policy_version: 'policy.v1', source_profiles: ['synthetic.lab'], max_age_ms: 60000 };
const bases = {
  snapshot: { grant: { template, client_id: 'client.alpha', grant_expires_at_ms: NOW + 100000, grant_limit: 5, permissions: [{ action: 'sandbox.execute', max_amount: 1000, max_duration: 600, max_price_sun: 1000 }] }, status: 'active', evidence: null, issued_at_ms: NOW, valid_until_ms: NOW + 30000 },
  admission: { context, intent_hash: intentHash(context), admission_id: 'admission.alpha', decision: 'admitted', reason: 'admitted', evaluated_at_ms: NOW, evaluated_uncertainty_ms: 0, grant_expires_at_ms: NOW + 100000, acceptance_expires_at_ms: NOW + 10000, first_submit_expires_at_ms: NOW + 30000, evidence: null },
};
const headers = { snapshot: { typ: 'atum-grant-status+jwt', alg: 'ES256', kid: 'authority-key' }, admission: { typ: 'atum-admission+jwt', alg: 'ES256', kid: 'authority-key' } };
function claims(role, data) {
  const issued = role === 'snapshot' ? data.issued_at_ms : data.evaluated_at_ms;
  const expires = role === 'snapshot' ? data.valid_until_ms : data.decision === 'admitted' ? data.first_submit_expires_at_ms : issued + 300000;
  return { iss: registration.issuer, aud: registration.audience, sub: context.scoped_subject, iat: Math.floor(issued / 1000), exp: Math.ceil(expires / 1000), jti: role === 'snapshot' ? 'snapshot.alpha' : data.admission_id, profile: role === 'snapshot' ? 'atum-grant-status-v1-draft.1' : 'atum-admission-v1-draft.1', data };
}

export async function generate() {
  const primary = await generateKeyPair('ES256'); const other = await generateKeyPair('ES256'); const cases = [];
  const sign = (raw, header, key = primary.privateKey) => new CompactSign(Buffer.from(raw)).setProtectedHeader(header).sign(key);
  async function add(name, role, expected, mutate = () => {}, overrides = {}, mutateClaims = () => {}, headerMutate = () => {}) {
    const data = structuredClone(bases[role]); mutate(data);
    const payload = claims(role, data); mutateClaims(payload);
    const header = structuredClone(headers[role]); headerMutate(header);
    cases.push({ name, role, expected, compact: await sign(JSON.stringify(payload), header), ...overrides });
  }
  await add('valid-snapshot', 'snapshot', 'valid');
  await add('valid-admission', 'admission', 'valid');
  await add('valid-required-evidence', 'snapshot', 'valid', d => { d.evidence = evidence; d.valid_until_ms = evidence.valid_until_ms; }, { evidence_policy: policy });
  await add('valid-denied', 'admission', 'valid', d => { Object.assign(d, { decision: 'denied', reason: 'grant_not_active', acceptance_expires_at_ms: null, first_submit_expires_at_ms: null }); });
  await add('historic-admission', 'admission', 'valid', undefined, { mode: 'inspect', clock: { now_ms: NOW + 1000000, uncertainty_ms: 0, healthy: true } });
  await add('historic-not-accept', 'admission', 'invalid', undefined, { clock: { now_ms: NOW + 1000000, uncertainty_ms: 0, healthy: true } });
  for (const role of ['snapshot', 'admission']) {
    await add(`${role}-wrong-issuer`, role, 'invalid', undefined, {}, c => { c.iss = 'elsewhere'; });
    await add(`${role}-wrong-audience`, role, 'invalid', undefined, {}, c => { c.aud = ['merx.synthetic.test']; });
    await add(`${role}-wrong-subject`, role, 'invalid', undefined, {}, c => { c.sub = 'other'; });
    await add(`${role}-unknown-kid`, role, 'invalid', undefined, {}, undefined, h => { h.kid = 'unregistered'; });
    await add(`${role}-role-confusion`, role, 'invalid', undefined, {}, undefined, h => { h.typ = 'at+jwt'; });
    await add(`${role}-remote-key`, role, 'invalid', undefined, {}, undefined, h => { h.jku = 'https://evil.invalid'; });
    await add(`${role}-extra-claims`, role, 'invalid', undefined, {}, c => { c.scope = 'admin'; });
    await add(`${role}-expiry-extended`, role, 'invalid', undefined, {}, c => { c.exp++; });
    await add(`${role}-bool-time`, role, 'invalid', undefined, {}, c => { c.iat = true; });
    await add(`${role}-fraction-time`, role, 'invalid', undefined, {}, c => { c.iat += .5; });
    await add(`${role}-unhealthy-clock`, role, 'invalid', undefined, { clock: { now_ms: NOW, uncertainty_ms: 0, healthy: false } });
    await add(`${role}-future-evidence`, role, 'invalid', d => { d.evidence = { ...evidence, issued_at_ms: NOW + 1 }; });
    const payload = claims(role, structuredClone(bases[role]));
    cases.push({ name: `${role}-wrong-signature`, role, expected: 'invalid', compact: await sign(JSON.stringify(payload), headers[role], other.privateKey) });
    cases.push({ name: `${role}-duplicate-JSON`, role, expected: 'invalid', compact: await sign(JSON.stringify(payload).replace('"iss":', '"iss":"duplicate","iss":'), headers[role]) });
    cases.push({ name: `${role}-noncanonical-b64`, role, expected: 'invalid', compact: (await sign(JSON.stringify(payload), headers[role])).replace('.', '=.') });
    cases.push({ name: `${role}-integral-JSON-number`, role, expected: 'valid', compact: await sign(JSON.stringify(payload).replace(`"iat":${payload.iat}`, `"iat":${payload.iat}.0`), headers[role]) });
  }
  for (const [field, value] of [['grant_limit', null], ['permissions', []], ['grant_expires_at_ms', NOW - 1]]) await add(`snapshot-invalid-${field}`, 'snapshot', 'invalid', d => { d.grant[field] = value; });
  await add('snapshot-nonactive', 'snapshot', 'invalid', d => { d.status = 'revoked'; });
  await add('snapshot-wrong-client', 'snapshot', 'invalid', undefined, { client_id: 'client.other' });
  await add('snapshot-required-evidence-missing', 'snapshot', 'invalid', undefined, { evidence_policy: policy });
  await add('snapshot-evidence-failed', 'snapshot', 'invalid', d => { d.evidence = { ...evidence, result: 'failed' }; d.valid_until_ms = evidence.valid_until_ms; }, { evidence_policy: policy });
  await add('snapshot-evidence-stale', 'snapshot', 'invalid', d => { d.evidence = { ...evidence, observed_at_ms: NOW - 60001 }; d.valid_until_ms = evidence.valid_until_ms; }, { evidence_policy: policy });
  for (const field of ['acceptance_expires_at_ms', 'first_submit_expires_at_ms']) await add(`admission-extended-${field}`, 'admission', 'invalid', d => { d[field]++; });
  await add('admission-action-hash-instead-of-context', 'admission', 'invalid', d => { d.intent_hash = d.context.action_hash; });
  await add('admission-accept-at-boundary', 'admission', 'invalid', undefined, { clock: { now_ms: NOW + 9999, uncertainty_ms: 1, healthy: true } });
  await add('admission-one-millisecond', 'admission', 'valid', d => { d.grant_expires_at_ms = NOW + 1; d.acceptance_expires_at_ms = NOW + 1; d.first_submit_expires_at_ms = NOW + 1; });
  await add('admission-uncertainty-exceeds-window', 'admission', 'invalid', d => { d.grant_expires_at_ms = NOW + 1; d.acceptance_expires_at_ms = NOW + 1; d.first_submit_expires_at_ms = NOW + 1; d.evaluated_uncertainty_ms = 1; });
  await add('admission-future-within-same-second', 'admission', 'invalid', d => { d.evaluated_at_ms++; d.acceptance_expires_at_ms++; d.first_submit_expires_at_ms++; });
  await add('admission-clock-underflow', 'admission', 'invalid', d => { d.evaluated_at_ms = 0; d.evaluated_uncertainty_ms = 1; d.grant_expires_at_ms = 100000; d.acceptance_expires_at_ms = 10000; d.first_submit_expires_at_ms = 30000; }, { clock: { now_ms: 2, uncertainty_ms: 0, healthy: true } });
  for (const field of ['operation_id', 'grant_id', 'account_binding_id', 'consent_hash']) await add(`admission-input-${field}-substitution`, 'admission', 'invalid', undefined, { context: { ...context, [field]: field === 'consent_hash' ? `sha256:${'c'.repeat(64)}` : 'other' } });
  return { synthetic: true, notice: 'Synthetic component fixtures; no production authority or private keys.', registration, context, action_request: action, client_id: 'client.alpha', clock: { now_ms: NOW, uncertainty_ms: 0, healthy: true }, public_keys: { 'authority-key': await exportJWK(primary.publicKey) }, cases };
}

if (process.argv[1].endsWith('generate-authority-vectors.mjs')) {
  if (!process.argv[2]) throw new Error('output path required');
  await writeFile(process.argv[2], JSON.stringify(await generate(), null, 2) + '\n', { flag: 'wx' });
}
