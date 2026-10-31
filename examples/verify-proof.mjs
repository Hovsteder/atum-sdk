import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createVerifier } from '@atum/verification';

// Offline example only: all values and time are deliberately synthetic.
// Use @atum/replay-postgres plus actual authority/admission for a live resource.
const vectors = JSON.parse(await readFile(new URL('../sdk/packages/verification/test/fixtures/proof-vectors.json', import.meta.url), 'utf8'));
const vector = vectors.cases.find(value => value.expected === 'proof_verified');
let nonce = structuredClone(vector.issued_nonce);
const replayStore = {
  async consume(input) {
    if (!nonce || nonce.nonce !== input.nonce || nonce.expires_at_ms <= input.now_upper_bound_ms
      || ['issuer', 'audience', 'agent_key_thumbprint', 'endpoint_url'].some(key => nonce[key] !== input[key])) return false;
    nonce = null;
    return true;
  },
};
const verifier = await createVerifier({ registration: vectors.registration,
  issuerKeys: vectors.issuer_keys, endpoint: vectors.endpoint,
  clock: () => vectors.clock, replayStore });
const result = await verifier.verifyProtectedRequest(vector.input);
assert.equal(result.proof_verified, true);
assert.equal(result.authorization_effect, 'none');
assert.equal(result.requires_admission, true);
await assert.rejects(verifier.verifyProtectedRequest(vector.input), { code: 'invalid_proof' });
console.log(JSON.stringify({ proof_verified: true, replay_rejected: true,
  authorization_effect: 'none', requires_admission: true, synthetic_fixture: true }));
