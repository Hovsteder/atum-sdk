import assert from 'node:assert/strict';
import test from 'node:test';
import { createProtectedHttpHandler, ProtectedHttpError } from '../src/node-http.mjs';

test('HTTP boundary exposes typed local errors and rejects mismatched endpoint or missing nonce issuer before construction', async () => {
  assert.equal(new ProtectedHttpError('invalid_request').code, 'invalid_request');
  const authorization = { proof: { endpoint: { method: 'POST', url: 'https://calendar.example/events' }, replayStore: { consume: async () => true } } };
  await assert.rejects(createProtectedHttpHandler({ authorization, endpoint: { method: 'POST', url: 'https://calendar.example/other' }, onAuthorized() {} }), TypeError);
  await assert.rejects(createProtectedHttpHandler({ authorization: { ...authorization, proof: { ...authorization.proof, replayStore: { consume: async () => true } } }, endpoint: authorization.proof.endpoint, onAuthorized() {} }), TypeError);
});
