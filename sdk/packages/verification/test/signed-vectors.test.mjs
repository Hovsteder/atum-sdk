import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createVerifier } from '../src/verifier.mjs';

const vectors = JSON.parse(await readFile(new URL('./fixtures/proof-vectors.json', import.meta.url)));

// Deliberately local test adapter. No production/persistent implementation exported.
function fixtureStore(issued) {
  let calls = 0;
  const used = new Set();
  const nonces = new Map(issued.map((n) => [n.nonce, n]));
  return {
    calls: () => calls,
    async consume(input) {
      calls += 1;
      const nonce = nonces.get(input.nonce);
      const key = JSON.stringify([input.issuer, input.audience, input.agent_key_thumbprint, input.proof_jti]);
      if (!nonce || nonce.expires_at_ms <= input.now_upper_bound_ms || used.has(key)
          || ['issuer', 'audience', 'agent_key_thumbprint', 'endpoint_url'].some((k) => nonce[k] !== input[k])) return false;
      used.add(key);
      nonces.delete(input.nonce);
      return true;
    },
  };
}

for (const vector of vectors.cases) {
  test(`signed vector: ${vector.name}`, async () => {
    const store = fixtureStore(vector.issued_nonce ? [vector.issued_nonce] : []);
    const verifier = await createVerifier({ registration: vectors.registration, issuerKeys: vectors.issuer_keys,
      endpoint: vectors.endpoint, clock: () => vectors.clock, replayStore: store });
    if (vector.expected === 'proof_verified') {
      const result = await verifier.verifyProtectedRequest(vector.input);
      assert.equal(result.proof_verified, true);
      assert.equal(result.authorization_effect, 'none');
      assert.equal(result.requires_admission, true);
    } else {
      await assert.rejects(verifier.verifyProtectedRequest(vector.input), { code: vector.expected });
    }
    assert.equal(store.calls(), vector.expected_replay_calls);
  });
}

test('signed vector: identical request replay rejected after first success', async () => {
  const vector = vectors.cases[0];
  const store = fixtureStore([vector.issued_nonce]);
  const verifier = await createVerifier({ registration: vectors.registration, issuerKeys: vectors.issuer_keys,
    endpoint: vectors.endpoint, clock: () => vectors.clock, replayStore: store });
  await verifier.verifyProtectedRequest(vector.input);
  await assert.rejects(verifier.verifyProtectedRequest(vector.input), { code: 'invalid_proof' });
  assert.equal(store.calls(), 2);
});
