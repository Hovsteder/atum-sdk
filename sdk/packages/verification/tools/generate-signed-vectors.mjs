// Offline synthetic interoperability fixtures. Private keys exist only in this process.
import { createHash, randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { CompactSign, calculateJwkThumbprint, exportJWK, generateKeyPair } from 'jose';
import { actionHash, intentHash } from '../src/context.mjs';

const encoder = new TextEncoder();
const clone = structuredClone;
const random = (n) => randomBytes(n).toString('base64url');
const digest = (s) => createHash('sha256').update(s, 'ascii').digest('base64url');
const atumFields = ['environment', 'tenant_id', 'resource_id', 'quota_scope_id',
  'operation_namespace', 'resource_profile_version', 'resource_profile_hash', 'policy_version',
  'grant_id', 'grant_version', 'consent_hash', 'account_binding_id', 'account_binding_version'];

function corruptSignature(jwt) {
  const segments = jwt.split('.');
  const signature = Buffer.from(segments[2], 'base64url');
  signature[0] ^= 1;
  segments[2] = signature.toString('base64url');
  return segments.join('.');
}

export async function generateSignedVectors() {
  const legacy = JSON.parse(await readFile(new URL('../../../candidate/vectors.json', import.meta.url)));
  const issuer = await generateKeyPair('RS256', { modulusLength: 2048 });
  const agent = await generateKeyPair('ES256');
  const issuerKey = { ...(await exportJWK(issuer.publicKey)), kid: 'synthetic-issuer-1', alg: 'RS256', use: 'sig' };
  const agentKey = await exportJWK(agent.publicKey);
  const thumbprint = await calculateJwkThumbprint(agentKey, 'sha256');
  const now = Date.UTC(2026, 9, 30, 12, 0, 0);
  const endpoint = { method: 'POST', url: 'https://resource.atum.invalid/v1/operations' };
  const action = { action: 'order.preview', parameters: { resource: 'ENERGY', amount: 42, duration: 3600 } };
  const context = { ...legacy.contexts[0].context, issuer: 'https://issuer.atum.invalid',
    audience: 'https://resource.atum.invalid', agent_key_thumbprint: thumbprint,
    action: action.action, action_hash: actionHash(action), account_binding_id: 'binding.synthetic', account_binding_version: 1 };
  const registration = { ...legacy.contexts[0].registration, issuer: context.issuer, audience: context.audience,
    account_required_actions: ['order.preview', 'sandbox.execute'] };
  const cases = [];

  async function add(name, expected = 'invalid_proof', options = {}) {
    const body = { context: clone(context), action_request: clone(action) };
    const claims = { iss: context.issuer, aud: context.audience, sub: context.scoped_subject,
      client_id: 'synthetic-client', jti: random(16), iat: now / 1000 - 10, exp: now / 1000 + 120,
      cnf: { jkt: thumbprint }, scope: 'atum:invoke', atum: { proof_profile: 'atum-dpop-v1-draft.1',
        ...Object.fromEntries(atumFields.map((k) => [k, context[k]])) } };
    options.token?.(claims);
    const tokenHeader = { typ: 'at+jwt', alg: 'RS256', kid: issuerKey.kid };
    options.tokenHeader?.(tokenHeader);
    let tokenText = JSON.stringify(claims);
    if (options.duplicateToken) tokenText = `{"iss":"duplicate",${tokenText.slice(1)}`;
    let token = await new CompactSign(encoder.encode(tokenText)).setProtectedHeader(tokenHeader).sign(issuer.privateKey);
    if (options.corruptToken) token = corruptSignature(token);
    const proofClaims = { jti: random(16), htm: endpoint.method, htu: endpoint.url, iat: now / 1000,
      ath: digest(token), nonce: random(32), atum_intent_hash: intentHash(context) };
    options.proof?.(proofClaims);
    const proofHeader = { typ: 'dpop+jwt', alg: 'ES256', jwk: clone(agentKey) };
    options.proofHeader?.(proofHeader);
    let proofText = JSON.stringify(proofClaims);
    if (options.duplicateProof) proofText = `{"jti":"duplicate",${proofText.slice(1)}`;
    let proof = await new CompactSign(encoder.encode(proofText)).setProtectedHeader(proofHeader).sign(agent.privateKey);
    if (options.corruptProof) proof = corruptSignature(proof);
    options.body?.(body);
    let bodyText = JSON.stringify(body);
    if (options.duplicateBody) bodyText = `{"context":{},${bodyText.slice(1)}`;
    cases.push({ name, expected, expected_replay_calls: options.replayCalls ?? (expected === 'proof_verified' ? 1 : 0),
      signatures: { token_valid: !options.corruptToken, proof_valid: !options.corruptProof },
      issued_nonce: options.unknownNonce ? null : { issuer: context.issuer, audience: context.audience,
        agent_key_thumbprint: thumbprint, endpoint_url: endpoint.url, nonce: proofClaims.nonce,
        expires_at_ms: options.expiredNonce ? now : now + 30_000 },
      input: { authorization: `DPoP ${token}`, dpop: proof, body: bodyText, method: endpoint.method, url: endpoint.url } });
  }

  await add('positive-bound-preview', 'proof_verified');
  for (const field of ['iss', 'aud', 'sub', 'scope']) {
    await add(`token-wrong-${field}`, 'invalid_proof', { token: (t) => { t[field] = 'other'; } });
  }
  for (const field of ['client_id', 'jti']) {
    await add(`token-newline-${field}`, 'invalid_proof', { token: (t) => { t[field] += '\n'; } });
  }
  for (const field of atumFields.filter((f) => !f.endsWith('_version'))) {
    await add(`token-wrong-${field}`, 'invalid_proof', { token: (t) => { t.atum[field] = 'other'; } });
  }
  for (const field of ['grant_version', 'account_binding_version']) {
    await add(`token-wrong-${field}`, 'invalid_proof', { token: (t) => { t.atum[field] += 1; } });
  }
  await add('token-wrong-cnf', 'invalid_proof', { token: (t) => { t.cnf.jkt = random(32); } });
  await add('token-expired-at-boundary', 'invalid_proof', { token: (t) => { t.exp = now / 1000; } });
  await add('token-excessive-lifetime', 'invalid_proof', { token: (t) => { t.exp = t.iat + 301; } });
  await add('token-future-nbf', 'invalid_proof', { token: (t) => { t.nbf = now / 1000 + 1; } });
  await add('token-future-iat', 'invalid_proof', { token: (t) => { t.iat = now / 1000 + 1; } });
  await add('token-unknown-claim', 'invalid_proof', { token: (t) => { t.extra = true; } });
  await add('token-duplicate-claim', 'invalid_proof', { duplicateToken: true });
  await add('token-wrong-type', 'invalid_proof', { tokenHeader: (h) => { h.typ = 'JWT'; } });
  await add('token-untrusted-kid', 'invalid_proof', { tokenHeader: (h) => { h.kid = 'untrusted'; } });
  await add('token-remote-key-header', 'invalid_proof', { tokenHeader: (h) => { h.jku = 'https://untrusted.invalid/jwks'; } });
  await add('token-invalid-signature', 'invalid_proof', { corruptToken: true });

  for (const [field, value] of Object.entries({ htm: 'GET', htu: `${endpoint.url}/other`, ath: random(32),
    atum_intent_hash: `sha256:${'0'.repeat(64)}`, jti: 'too-short' })) {
    await add(`proof-wrong-${field}`, 'invalid_proof', { proof: (p) => { p[field] = value; } });
  }
  await add('proof-future-iat', 'invalid_proof', { proof: (p) => { p.iat += 1; } });
  await add('proof-stale-iat', 'invalid_proof', { proof: (p) => { p.iat -= 61; } });
  await add('proof-unknown-nonce', 'invalid_proof', { unknownNonce: true, replayCalls: 1 });
  await add('proof-expired-nonce', 'invalid_proof', { expiredNonce: true, replayCalls: 1 });
  await add('proof-malformed-nonce', 'invalid_proof', { proof: (p) => { p.nonce = 'short'; } });
  await add('proof-unknown-claim', 'invalid_proof', { proof: (p) => { p.extra = true; } });
  await add('proof-duplicate-claim', 'invalid_proof', { duplicateProof: true });
  await add('proof-wrong-type', 'invalid_proof', { proofHeader: (h) => { h.typ = 'JWT'; } });
  await add('proof-private-key-header', 'invalid_proof', { proofHeader: (h) => { h.jwk.d = 'not-a-private-key'; } });
  await add('proof-invalid-signature', 'invalid_proof', { corruptProof: true });
  await add('body-changed-amount', 'invalid_request', { body: (b) => { b.action_request.parameters.amount += 1; } });
  await add('body-changed-operation', 'invalid_proof', { body: (b) => { b.context.operation_id = 'different-operation'; } });
  await add('body-unknown-field', 'invalid_request', { body: (b) => { b.extra = true; } });
  await add('body-duplicate-context', 'invalid_request', { duplicateBody: true });
  return { synthetic: true, proof_profile: 'atum-dpop-v1-draft.1', context_protocol: '0.1.0-draft.2',
    notice: 'Public test keys only. Fixed historical test clock; no authorization or real owner evidence.',
    clock: { now_ms: now, uncertainty_ms: 0, healthy: true }, endpoint, registration,
    issuer_keys: [issuerKey], agent_public_key: agentKey, cases };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.length !== 3) throw new Error('Usage: node tools/generate-signed-vectors.mjs NEW_OUTPUT_PATH');
  const result = await generateSignedVectors();
  await writeFile(process.argv[2], `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx', mode: 0o644 });
  console.log(`Wrote ${result.cases.length} synthetic signed cases; no private keys saved.`);
}
