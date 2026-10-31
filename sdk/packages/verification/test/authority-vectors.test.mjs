import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createAuthorityVerifier } from '../src/authority.mjs';

for (const file of ['vectors.json', 'python-vectors.json']) {
const vectors = JSON.parse(await readFile(new URL(`../../../authority/${file}`, import.meta.url)));
for (const vector of vectors.cases) test(`authority cross-language vector: ${vector.name}`, async () => {
  const verifier = await createAuthorityVerifier({ registration: vectors.registration, evidencePolicy: vector.evidence_policy ?? null, issuerKeys: vectors.public_keys, clock: () => vector.clock ?? vectors.clock });
  const context = vector.context ?? vectors.context; const action = vector.action_request ?? vectors.action_request;
  const check = vector.role === 'snapshot' ? verifier.verifyGrantSnapshot(vector.compact, context, action, vector.client_id ?? vectors.client_id) : verifier.verifyAdmission(vector.compact, context, action, { mode: vector.mode ?? 'accept' });
  if (vector.expected === 'valid') {
    const result = await check;
    if (vector.mode === 'inspect') { assert.equal(result.authorization_effect, 'none'); assert.equal(result.historical, true); }
  } else await assert.rejects(check);
});
}
