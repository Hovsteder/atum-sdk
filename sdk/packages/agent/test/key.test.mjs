import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify, webcrypto } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';

import { AgentError, createAgentKey, createWebCryptoAgentKey } from '../src/index.mjs';

const vector = JSON.parse(await readFile(new URL('../../../protocol/owner-consent/owner-consent-v1.json', import.meta.url)));
const privateJwk = vector.test_private_jwk;
const publicJwk = Object.freeze({ kty: privateJwk.kty, crv: privateJwk.crv, x: privateJwk.x, y: privateJwk.y });
const privateKey = createPrivateKey({ key: privateJwk, format: 'jwk' });
const publicKey = createPublicKey({ key: publicJwk, format: 'jwk' });

function externalSigner(overrides = {}) {
  return {
    publicJwk,
    timeoutMs: 100,
    sign: async (data) => nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' }),
    ...overrides,
  };
}

test('external key signs with a frozen public snapshot and independently verifiable raw ES256 bytes', async () => {
  const config = externalSigner();
  const keyPromise = createAgentKey(config);
  config.publicJwk = { ...publicJwk, x: 'A'.repeat(43) };
  const key = await keyPromise;
  const input = new TextEncoder().encode('eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhZ2VudC0xIn0');
  const signature = await key.sign(input);

  assert.equal(signature.byteLength, 64);
  assert.equal(nodeVerify('sha256', input, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature), true);
  assert.deepEqual(key.publicJwk, publicJwk);
  assert.equal(key.thumbprint, 'xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M');
  assert.equal(Object.isFrozen(key), true);
  assert.equal(Object.isFrozen(key.publicJwk), true);
});

test('WebCrypto adapter uses a non-exported P-256 private CryptoKey', async () => {
  const cryptoKey = await webcrypto.subtle.importKey('jwk', privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const key = await createWebCryptoAgentKey({ publicJwk, privateKey: cryptoKey });
  const input = new TextEncoder().encode('protected.payload');
  const signature = await key.sign(input);
  assert.equal(signature.byteLength, 64);
  assert.equal(nodeVerify('sha256', input, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature), true);
  assert.equal(Object.hasOwn(key, 'privateKey'), false);
});

test('key snapshots input before await and captures returned signature bytes before later mutation', async () => {
  let callbackInput;
  let callbackSignature;
  const key = await createAgentKey(externalSigner({ sign: async (data) => {
    callbackInput = data;
    callbackSignature = nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
    setTimeout(() => callbackSignature.fill(0), 0);
    return callbackSignature;
  } }));
  const input = new TextEncoder().encode('original.bytes');
  const original = input.slice();
  const pending = key.sign(input);
  input.fill(0);
  const result = await pending;
  callbackInput.fill(1);
  await delay(5);

  assert.equal(nodeVerify('sha256', original, { key: publicKey, dsaEncoding: 'ieee-p1363' }, result), true);
  assert.notDeepEqual(result, callbackSignature);
});

test('key copies typed-array subclasses without dispatching hostile species', async () => {
  let speciesCalls = 0;
  class HostileBytes extends Uint8Array {
    static get [Symbol.species]() {
      speciesCalls += 1;
      throw new Error('species must not run');
    }
  }
  const key = await createAgentKey(externalSigner({ sign: async (data) => {
    const signature = nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
    return new HostileBytes(signature);
  } }));
  const original = new TextEncoder().encode('species.safe');
  const input = new HostileBytes(original);
  const signature = await key.sign(input);
  input.fill(0);
  assert.equal(signature.constructor, Uint8Array);
  assert.equal(nodeVerify('sha256', original, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature), true);
  assert.equal(speciesCalls, 0);
});

test('key rejects callback mutation of signing input and wrong signature without returning proof bytes', async () => {
  const mutating = await createAgentKey(externalSigner({ sign: async (data) => {
    data.fill(0);
    return nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  } }));
  await assert.rejects(mutating.sign(new TextEncoder().encode('retained')), (error) => error instanceof AgentError && error.code === 'invalid_proof');

  const wrong = await createAgentKey(externalSigner({ sign: async () => new Uint8Array(64) }));
  await assert.rejects(wrong.sign(new Uint8Array([1, 2, 3])), (error) => error instanceof AgentError && error.code === 'invalid_proof');
});

test('key bounds signer wait and redacts callback failures', async () => {
  const never = await createAgentKey(externalSigner({ timeoutMs: 20, sign: async () => new Promise(() => {}) }));
  await assert.rejects(never.sign(new Uint8Array([1])), (error) => error instanceof AgentError
    && error.code === 'temporarily_unavailable' && !error.message.includes('secret'));

  const throwing = await createAgentKey(externalSigner({ sign: async () => { throw new Error('secret-private-key-detail'); } }));
  await assert.rejects(throwing.sign(new Uint8Array([1])), (error) => error instanceof AgentError
    && error.code === 'temporarily_unavailable' && !error.message.includes('secret-private-key-detail'));
});

test('key rejects accessor, symbol, private and extra configuration without invoking getters', async () => {
  let getterCalls = 0;
  const getterJwk = {};
  for (const [name, value] of Object.entries(publicJwk)) {
    Object.defineProperty(getterJwk, name, name === 'x'
      ? { enumerable: true, get() { getterCalls += 1; return value; } }
      : { enumerable: true, value });
  }
  const symbolConfig = externalSigner();
  symbolConfig[Symbol('extra')] = true;
  const cases = [
    externalSigner({ publicJwk: getterJwk }),
    symbolConfig,
    externalSigner({ publicJwk: privateJwk }),
    externalSigner({ extra: true }),
    externalSigner({ timeoutMs: 0 }),
    externalSigner({ timeoutMs: 5001 }),
  ];
  for (const value of cases) await assert.rejects(createAgentKey(value), TypeError);
  assert.equal(getterCalls, 0);
});

test('sign options are closed and cannot invoke accessors', async () => {
  const key = await createAgentKey(externalSigner());
  let calls = 0;
  const options = {};
  Object.defineProperty(options, 'timeoutMs', { enumerable: true, get() { calls += 1; return 20; } });
  assert.throws(() => key.sign(new Uint8Array([1]), options), TypeError);
  assert.throws(() => key.sign(new Uint8Array([1]), { timeoutMs: 101 }), TypeError);
  assert.equal(calls, 0);
});

test('signing input is bounded before the signer is called', async () => {
  let calls = 0;
  const key = await createAgentKey(externalSigner({ sign: async (data) => {
    calls += 1;
    return nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  } }));
  assert.throws(() => key.sign(new Uint8Array(16 * 1024 + 1)), TypeError);
  assert.equal(calls, 0);
});
