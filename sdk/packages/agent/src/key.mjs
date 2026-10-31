import { createHash, webcrypto } from 'node:crypto';

import { canonical } from './strict.mjs';

const SAFE_CODES = new Set(['invalid_request', 'invalid_proof', 'access_denied', 'invalid_grant', 'expired_token', 'temporarily_unavailable']);
const JWK_FIELDS = ['kty', 'crv', 'x', 'y'];
const CONFIG_FIELDS = new Set(['publicJwk', 'sign', 'timeoutMs']);
const WEBCRYPTO_FIELDS = new Set(['publicJwk', 'privateKey', 'timeoutMs']);
const OPTION_FIELDS = new Set(['timeoutMs']);
const B64_32 = /^[A-Za-z0-9_-]{43}$/;
const MAX_SIGNING_INPUT = 16 * 1024;
const typedArrayByteLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength').get;
const keyDetails = new WeakMap();

export class AgentError extends Error {
  constructor(code) {
    if (!SAFE_CODES.has(code)) throw new TypeError('invalid error code');
    super('agent operation failed');
    Object.defineProperty(this, 'name', { value: 'AgentError', enumerable: false });
    Object.defineProperty(this, 'code', { value: code, enumerable: true });
  }
}

function invalidConfig() { throw new TypeError('invalid config'); }
function invalidInput() { throw new TypeError('invalid input'); }

function record(value, fields, invalid) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid();
  let prototype; let keys; let descriptors;
  try {
    prototype = Object.getPrototypeOf(value);
    keys = Reflect.ownKeys(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch { invalid(); }
  if (prototype !== Object.prototype || keys.some((key) => typeof key !== 'string')
      || keys.some((key) => !fields.has(key)) || keys.length !== Object.keys(descriptors).length) invalid();
  const result = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) invalid();
    result[key] = descriptor.value;
  }
  return result;
}

function coordinate(value) {
  if (typeof value !== 'string' || !B64_32.test(value)) invalidConfig();
  let bytes;
  try { bytes = Buffer.from(value, 'base64url'); } catch { invalidConfig(); }
  if (bytes.byteLength !== 32 || bytes.toString('base64url') !== value) invalidConfig();
  return value;
}

function jwkCopy(value) {
  const source = record(value, new Set(JWK_FIELDS), invalidConfig);
  if (Reflect.ownKeys(source).length !== JWK_FIELDS.length || source.kty !== 'EC' || source.crv !== 'P-256') invalidConfig();
  const copy = { kty: 'EC', crv: 'P-256', x: coordinate(source.x), y: coordinate(source.y) };
  return Object.freeze(copy);
}

function timeout(value, upper, invalid) {
  if (!Number.isSafeInteger(value) || value < 1 || value > upper) invalid();
  return value;
}

function bytes(input, maximum, invalid = invalidInput) {
  if (!ArrayBuffer.isView(input) || !(input instanceof Uint8Array)) invalid();
  try {
    if (typedArrayByteLength.call(input) > maximum) invalid();
    return new Uint8Array(input);
  } catch (error) {
    if (error instanceof AgentError) throw error;
    invalid();
  }
}

function signOptions(value, maximum) {
  if (value === undefined) return maximum;
  const options = record(value, OPTION_FIELDS, invalidInput);
  if (Reflect.ownKeys(options).length !== 1) invalidInput();
  return timeout(options.timeoutMs, maximum, invalidInput);
}

async function publicCryptoKey(jwk) {
  try {
    return await webcrypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  } catch { invalidConfig(); }
}

function thumbprint(jwk) {
  return createHash('sha256').update(canonical({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }), 'ascii').digest('base64url');
}

export async function createAgentKey(value) {
  const config = record(value, CONFIG_FIELDS, invalidConfig);
  if (!Object.hasOwn(config, 'publicJwk') || !Object.hasOwn(config, 'sign')
      || (Reflect.ownKeys(config).length !== 2 && Reflect.ownKeys(config).length !== 3)
      || typeof config.sign !== 'function') invalidConfig();
  const publicJwk = jwkCopy(config.publicJwk);
  const maximum = Object.hasOwn(config, 'timeoutMs') ? timeout(config.timeoutMs, 5000, invalidConfig) : 5000;
  const signer = config.sign;
  const verificationKey = await publicCryptoKey(publicJwk);

  function sign(input, options) {
    const original = bytes(input, MAX_SIGNING_INPUT);
    const budget = signOptions(options, maximum);
    const supplied = original.slice();
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (error, result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(error); else resolve(result);
      };
      const timer = setTimeout(() => finish(new AgentError('temporarily_unavailable')), budget);
      (async () => {
        let returned;
        try { returned = await signer(supplied); } catch { return finish(new AgentError('temporarily_unavailable')); }
        let signature;
        try { signature = bytes(returned, 64, () => { throw new AgentError('invalid_proof'); }); } catch (error) { return finish(error instanceof AgentError ? error : new AgentError('invalid_proof')); }
        if (signature.byteLength !== 64) return finish(new AgentError('invalid_proof'));
        let verified;
        try { verified = await webcrypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, verificationKey, signature, original); }
        catch { return finish(new AgentError('invalid_proof')); }
        if (!verified) return finish(new AgentError('invalid_proof'));
        return finish(null, new Uint8Array(signature));
      })();
    });
  }

  const key = Object.freeze({ publicJwk, thumbprint: thumbprint(publicJwk), sign });
  keyDetails.set(key, Object.freeze({ timeoutMs: maximum }));
  return key;
}

export async function createWebCryptoAgentKey(value) {
  const config = record(value, WEBCRYPTO_FIELDS, invalidConfig);
  if ((Reflect.ownKeys(config).length !== 2 && Reflect.ownKeys(config).length !== 3)
      || !Object.hasOwn(config, 'publicJwk') || !Object.hasOwn(config, 'privateKey')) invalidConfig();
  const privateKey = config.privateKey;
  if (!(privateKey instanceof CryptoKey) || privateKey.type !== 'private' || privateKey.algorithm?.name !== 'ECDSA'
      || privateKey.algorithm?.namedCurve !== 'P-256' || !privateKey.usages.includes('sign')) invalidConfig();
  const adapter = {
    publicJwk: config.publicJwk,
    sign: async (data) => new Uint8Array(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data)),
  };
  if (Object.hasOwn(config, 'timeoutMs')) adapter.timeoutMs = config.timeoutMs;
  return createAgentKey(adapter);
}

export function assertAgentKey(value) {
  if (!keyDetails.has(value)) invalidConfig();
  return value;
}

export function agentKeyTimeout(value) {
  assertAgentKey(value);
  return keyDetails.get(value).timeoutMs;
}
