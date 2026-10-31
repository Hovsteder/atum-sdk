import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createVerifier } from '../src/verifier.mjs';

const vectors = JSON.parse(await readFile(new URL('./fixtures/proof-vectors.json', import.meta.url)));
const input = () => structuredClone(vectors.cases[0].input);
function configuration(consume = async () => true) {
  return { registration: structuredClone(vectors.registration), issuerKeys: structuredClone(vectors.issuer_keys),
    endpoint: structuredClone(vectors.endpoint), clock: () => ({ ...vectors.clock }), replayStore: { consume } };
}

test('captures trusted configuration before the factory first yields', async () => {
  let calls = 0;
  const config = configuration(async () => { calls += 1; return true; });
  const building = createVerifier(config);
  config.clock = () => { throw new Error('replaced'); };
  config.replayStore.consume = async () => false;
  config.registration.policy_version = 'replaced';
  config.registration.account_required_actions.push('prices.read');
  config.issuerKeys[0].kid = 'replaced';
  config.endpoint.url += '/replaced';
  const verifier = await building;
  const result = await verifier.verifyProtectedRequest(input());
  assert.equal(result.proof_verified, true);
  assert.equal(calls, 1);
});

test('normalizes unexpected registration host errors to invalid config', async () => {
  const config = configuration();
  Object.defineProperty(config.registration, 'issuer', { enumerable: true, get() { throw new RangeError('host getter'); } });
  await assert.rejects(createVerifier(config), TypeError);
});

test('captures request bytes and headers before asynchronous signatures', async () => {
  const verifier = await createVerifier(configuration());
  const request = input();
  request.body = new TextEncoder().encode(request.body);
  const checking = verifier.verifyProtectedRequest(request);
  request.body.fill(0);
  request.dpop = 'replaced';
  request.authorization = 'Bearer replaced';
  request.url += '/replaced';
  const result = await checking;
  assert.equal(result.proof_verified, true);
  assert.equal(result.context.operation_id, 'op-001');
});

test('oversized and ambiguous HTTP inputs never reach the replay adapter', async () => {
  let calls = 0;
  const verifier = await createVerifier(configuration(async () => { calls += 1; return true; }));
  const malformed = [
    { body: new Uint8Array(32769) }, { body: 'x'.repeat(32769) },
    { authorization: `DPoP ${'a'.repeat(16417)}` }, { dpop: 'x'.repeat(8193) },
    { authorization: ['DPoP test'] }, { dpop: ['a.b.c'] },
    { authorization: `${input().authorization},${input().authorization}` },
    { authorization: `${input().authorization}\n` },
    { authorization: input().authorization.replace('DPoP ', 'Bearer ') },
    { method: 'GET' }, { url: `${vectors.endpoint.url}?ignored=yes` },
    { body: '{"context":{},"context":{}}' },
  ];
  for (const patch of malformed) {
    await assert.rejects(verifier.verifyProtectedRequest({ ...input(), ...patch }), { code: 'invalid_request' });
  }
  assert.equal(calls, 0);
});

test('never treats a truthy store response as successful atomic replay consumption', async () => {
  for (const response of [false, undefined, null, 1, 'true', { accepted: true }]) {
    const verifier = await createVerifier(configuration(async () => response));
    await assert.rejects(verifier.verifyProtectedRequest(input()), { code: 'invalid_proof' });
  }
});

test('rejects RSA/HMAC algorithm confusion and unsigned access tokens', async () => {
  const verifier = await createVerifier(configuration());
  const original = input();
  const payload = original.authorization.split(' ')[1].split('.')[1];
  const header = Buffer.from(JSON.stringify({ typ: 'at+jwt', alg: 'HS256', kid: vectors.issuer_keys[0].kid })).toString('base64url');
  const signed = `${header}.${payload}`;
  const mac = createHmac('sha256', vectors.issuer_keys[0].n).update(signed).digest('base64url');
  await assert.rejects(verifier.verifyProtectedRequest({ ...original, authorization: `DPoP ${signed}.${mac}` }), { code: 'invalid_proof' });
  await assert.rejects(verifier.verifyProtectedRequest({ ...original, authorization: `DPoP ${header}.${payload}.` }), { code: 'invalid_request' });
});

test('key registry refuses private keys, padded integers, duplicate IDs and implicit trust discovery', async () => {
  for (const mutate of [
    (c) => { c.issuerKeys[0].d = 'never-real-secret'; },
    (c) => { c.issuerKeys[0].n += '='; },
    (c) => { c.issuerKeys[0].n = Buffer.concat([Buffer.from([0]), Buffer.from(c.issuerKeys[0].n, 'base64url')]).toString('base64url'); },
    (c) => { c.issuerKeys.push({ ...c.issuerKeys[0] }); },
    (c) => { c.jwks_uri = 'https://untrusted.invalid/jwks'; },
    (c) => { delete c.clock; },
    (c) => { delete c.replayStore; },
  ]) {
    const config = configuration();
    mutate(config);
    await assert.rejects(createVerifier(config), TypeError);
  }
});

test('clock uncertainty applies strictly and invalid measurements fail unavailable', async () => {
  for (const clock of [
    { ...vectors.clock, uncertainty_ms: 1001 },
    { ...vectors.clock, now_ms: Number.MAX_SAFE_INTEGER, uncertainty_ms: 1 },
    { ...vectors.clock, healthy: 'true' },
  ]) {
    const config = configuration(); config.clock = () => clock;
    const verifier = await createVerifier(config);
    await assert.rejects(verifier.verifyProtectedRequest(input()), { code: 'temporarily_unavailable' });
  }
  const config = configuration();
  config.clock = () => ({ now_ms: vectors.clock.now_ms + 59_001, uncertainty_ms: 1000, healthy: true });
  const verifier = await createVerifier(config);
  await assert.rejects(verifier.verifyProtectedRequest(input()), { code: 'invalid_proof' });
});

test('rechecks token and proof validity after a delayed replay commit', async () => {
  let tick = 0; let consumed = 0;
  const config = configuration(async () => { consumed += 1; return true; });
  config.clock = () => ({ ...vectors.clock, now_ms: vectors.clock.now_ms + (tick++ >= 2 ? 120_000 : 0) });
  const verifier = await createVerifier(config);
  await assert.rejects(verifier.verifyProtectedRequest(input()), { code: 'invalid_proof' });
  assert.equal(consumed, 1); // Commit may have completed; caller must make a fresh proof.
});

test('fails unavailable if clock health is lost while replay storage commits', async () => {
  let tick = 0; let consumed = 0;
  const config = configuration(async () => { consumed += 1; return true; });
  config.clock = () => ({ ...vectors.clock, healthy: tick++ < 2 });
  const verifier = await createVerifier(config);
  await assert.rejects(verifier.verifyProtectedRequest(input()), { code: 'temporarily_unavailable' });
  assert.equal(consumed, 1);
});
