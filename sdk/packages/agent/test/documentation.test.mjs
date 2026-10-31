import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { createAgentKey } from '@atum/agent';
import { publicJwk, requestInput, resourceExample, signingPorts, startDocumentationFixture } from './documentation-fixture.mjs';

const packageRoot = fileURLToPath(new URL('..', import.meta.url));
const require = createRequire(import.meta.url);
const publicNames = ['AgentError', 'ResourceInvocationError', 'createAgentClient', 'createAgentKey', 'createProtectedRequestSigner',
  'createProtectedResourceClient', 'createRequestProofClient', 'createWebCryptoAgentKey'];

function executableBlocks(markdown) {
  return [...markdown.matchAll(/```js executable\n([\s\S]*?)```/g)].map(match => match[1]);
}

async function loadExamples(t) {
  const directory = mkdtempSync(path.join(packageRoot, '.documentation-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const examples = new Map();
  const sources = new Map();
  let count = 0;
  for (const name of ['README.md', 'PROFILE.md']) {
    const blocks = executableBlocks(readFileSync(path.join(packageRoot, name), 'utf8'));
    assert.ok(blocks.length >= 4, `${name} must contain executable key, flow, refresh and resource examples`);
    for (const source of blocks) {
      const file = path.join(directory, `${name.toLowerCase()}-${count}.mjs`);
      writeFileSync(file, source);
      const loaded = await import(`${pathToFileURL(file).href}?case=${count}`);
      const exported = Object.entries(loaded).filter(([, value]) => typeof value === 'function');
      assert.equal(exported.length, 1, `${name} example must export one callable function`);
      const [[functionName, callable]] = exported;
      assert.equal(examples.has(functionName), false, `duplicate documented function ${functionName}`);
      examples.set(functionName, callable);
      sources.set(functionName, source);
      count += 1;
    }
  }
  return { directory, examples, sources };
}

async function withFixture(run) {
  const fixture = await startDocumentationFixture();
  try { return await run(fixture); } finally { await fixture.close(); }
}

async function keyAndConfig(examples, fixture, profile = false) {
  const ports = signingPorts();
  const key = profile
    ? await examples.get('agentKeyFromSigningPort')({ publicJwk, signingPort: ports.signingPort })
    : await examples.get('createHardwareBackedKey')({ publicJwk, hardwareKey: ports.hardwareKey });
  const common = { registration: fixture.registration, endpoints: fixture.endpoints,
    issuerCaPem: fixture.issuerCaPem, key, clock: fixture.clock };
  const config = profile
    ? examples.get('registeredAgentConfig')({ ...common, client: fixture.client })
    : examples.get('createAgentConfiguration')({ ...common, registeredClient: fixture.client });
  return { key, config };
}

function proofClaims(compact) {
  return JSON.parse(Buffer.from(compact.split('.')[1], 'base64url'));
}

function deviceInput() {
  const { redirect_uri: _redirectUri, ...input } = requestInput();
  return input;
}

test('every marked README and profile example is imported and called through public exports', { timeout: 60_000 }, async t => {
  const { examples } = await loadExamples(t);
  assert.deepEqual([...examples.keys()].sort(), [
    'agentKeyFromSigningPort', 'authorizeAndRefreshWithCode', 'authorizeWithDevice', 'codeGrantWithRotation',
    'createAgentConfiguration', 'createHardwareBackedKey', 'deviceGrant',
    'prepareRegisteredRequest', 'protectedRequestWithNonce', 'registeredAgentConfig', 'signProtectedRequest',
  ]);

  await withFixture(async fixture => {
    const { key, config } = await keyAndConfig(examples, fixture, true);
    assert.equal(key.thumbprint.length, 43);
    const input = requestInput();
    const prepared = await examples.get('prepareRegisteredRequest')({ config, input: {
      flow: 'authorization_code', permissions: input.permissions, grant_limit: input.grant_limit,
      grant_expires_at_ms: input.grant_expires_at_ms, redirect_uri: input.redirect_uri,
      code_challenge: 'A'.repeat(43), state: 'B'.repeat(32),
    } });
    assert.equal(prepared.request.request_id, '123e4567-e89b-42d3-a456-426614174000');
    assert.deepEqual(fixture.state().routeCalls, ['/atum/request/options', '/atum/request/verify']);
  });

  await withFixture(async fixture => {
    const { config } = await keyAndConfig(examples, fixture);
    const result = await examples.get('authorizeAndRefreshWithCode')({
      config, request: requestInput(), authorizeOwner: async shown => {
        assert.equal(new URL(shown.authorizationUrl).origin, fixture.registration.issuer);
        assert.equal(shown.requestId, '123e4567-e89b-42d3-a456-426614174000');
        return fixture.callbackUrl();
      },
    });
    assert.equal(result.first.refresh_token, 'R'.repeat(43));
    assert.equal(result.rotated.refresh_token, 'S'.repeat(43));
    assert.equal(fixture.state().tokenCalls, 4);
  });

  await withFixture(async fixture => {
    const { config } = await keyAndConfig(examples, fixture, true);
    const result = await examples.get('codeGrantWithRotation')({
      config, request: requestInput(), authorizeOwner: async authorizationUrl => {
        assert.equal(new URL(authorizationUrl).origin, fixture.registration.issuer);
        return fixture.callbackUrl();
      },
    });
    assert.equal(result.tokens.refresh_token, 'R'.repeat(43));
    assert.equal(result.rotated.refresh_token, 'S'.repeat(43));
  });

  await withFixture(async fixture => {
    const { config } = await keyAndConfig(examples, fixture);
    const tokens = await examples.get('authorizeWithDevice')({
      config, request: deviceInput(), signal: new AbortController().signal, presentToOwner: async shown => {
        assert.equal(shown.userCode, 'BCDF-GHJK');
        assert.equal(shown.verificationUriComplete, `${fixture.registration.issuer}/device?user_code=BCDF-GHJK`);
      },
    });
    assert.equal(tokens.refresh_token, 'R'.repeat(43));
    assert.equal(fixture.state().tokenCalls, 2);
  });

  await withFixture(async fixture => {
    const { config } = await keyAndConfig(examples, fixture, true);
    const tokens = await examples.get('deviceGrant')({
      config, request: deviceInput(), signal: new AbortController().signal, display: async shown => {
        assert.equal(shown.userCode, 'BCDF-GHJK');
        assert.equal(shown.uri, `${fixture.registration.issuer}/device`);
      },
    });
    assert.equal(tokens.refresh_token, 'R'.repeat(43));
  });

  for (const [functionName, displayName] of [['authorizeWithDevice', 'presentToOwner'], ['deviceGrant', 'display']]) {
    await withFixture(async fixture => {
      const { config } = await keyAndConfig(examples, fixture, functionName === 'deviceGrant');
      const controller = new AbortController();
      controller.abort();
      const unhandled = [];
      const onUnhandled = reason => unhandled.push(reason);
      process.on('unhandledRejection', onUnhandled);
      try {
        const delayedDisplay = async () => new Promise(resolve => setTimeout(resolve, 25));
        await assert.rejects(examples.get(functionName)({ config, request: deviceInput(), signal: controller.signal,
          [displayName]: delayedDisplay }), error => error?.code === 'temporarily_unavailable');
        await new Promise(resolve => setImmediate(resolve));
        assert.deepEqual(unhandled, []);
        assert.equal(fixture.state().tokenCalls, 0);
      } finally {
        process.removeListener('unhandledRejection', onUnhandled);
      }
    });
  }

  const ports = signingPorts();
  const readmeKey = await examples.get('createHardwareBackedKey')({ publicJwk, hardwareKey: ports.hardwareKey });
  const resource = resourceExample(readmeKey);
  const signed = await examples.get('signProtectedRequest')({
    key: readmeKey, registration: resource.registration, endpoint: resource.endpoint, clock: resource.clock,
    accessToken: resource.accessToken, context: resource.context, actionRequest: resource.actionRequest,
    obtainTrustedNonce: async challenge => {
      assert.equal(proofClaims(challenge.dpop).nonce, undefined);
      return resource.nonce;
    },
  });
  assert.equal(proofClaims(signed.dpop).nonce, resource.nonce);

  const profileKey = await examples.get('agentKeyFromSigningPort')({ publicJwk, signingPort: ports.signingPort });
  const profileResource = resourceExample(profileKey);
  const continued = await examples.get('protectedRequestWithNonce')({
    key: profileKey, registration: profileResource.registration, endpoint: profileResource.endpoint,
    clock: profileResource.clock, accessToken: profileResource.accessToken, context: profileResource.context,
    actionRequest: profileResource.actionRequest, exchangeChallenge: async challenge => {
      assert.equal(proofClaims(challenge.dpop).nonce, undefined);
      return profileResource.nonce;
    },
  });
  assert.equal(proofClaims(continued.protectedRequest.dpop).nonce, profileResource.nonce);
  assert.equal(continued.challengeRequest.body, continued.protectedRequest.body);
});

test('root and documented subpath exports load from ESM and CommonJS', async () => {
  const esm = await import('@atum/agent');
  const cjs = require('@atum/agent');
  assert.deepEqual(Object.keys(esm).sort(), publicNames);
  assert.deepEqual(Object.keys(cjs).sort(), publicNames);
  for (const subpath of ['client', 'key', 'request-proof', 'resource-proof', 'resource-client']) {
    const specifier = `@atum/agent/${subpath}`;
    assert.ok(Object.keys(await import(specifier)).length > 0);
    assert.ok(Object.keys(require(specifier)).length > 0);
  }
});

test('executing a documented flow catches a wrong public method name', async t => {
  const { directory, sources } = await loadExamples(t);
  const original = sources.get('authorizeAndRefreshWithCode');
  const altered = original.replace('beginAuthorizationCode(request)', 'beginAuthorizationCodes(request)');
  assert.notEqual(altered, original);
  const file = path.join(directory, 'wrong-method.mjs');
  writeFileSync(file, altered);
  const loaded = await import(`${pathToFileURL(file).href}?wrong-method`);
  await withFixture(async fixture => {
    const key = await createAgentKey({ publicJwk, sign: signingPorts().hardwareKey.signEs256 });
    const config = { registration: fixture.registration, client: fixture.client, endpoints: fixture.endpoints,
      tls: { ca: fixture.issuerCaPem }, key, clock: fixture.clock, timeoutMs: 5_000, maxConcurrent: 4 };
    await assert.rejects(loaded.authorizeAndRefreshWithCode({
      config, request: requestInput(), authorizeOwner: async () => fixture.callbackUrl(),
    }), TypeError);
    assert.equal(fixture.state().routeCalls.length, 0);
  });
});
