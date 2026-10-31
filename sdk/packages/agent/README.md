# ATUM Agent SDK

`@atum/agent` is the Node.js SDK for a registered ATUM OAuth agent. It
prepares signed owner-consent requests, runs PAR/PKCE authorization-code and
Device flows, rotates refresh tokens, and signs protected resource requests.

This developer preview supports the pinned sandbox profile on Node.js 22.12
or newer. Install it through the repository root workspace; npm registry
publication is separate. See [PROFILE.md](./PROFILE.md)
for the complete configuration and wire contract.

## TypeScript declarations

The package ships NodeNext-compatible declarations for the root import and the
documented `client`, `key`, `request-proof`, `resource-proof`, and `resource-client` subpaths.
They describe the public configuration, signing port, flows, token artifacts,
resource context/action, signature artifact, and `AgentError.code` union. The
types reflect the action-specific public fields, but TypeScript cannot prove
runtime closed-object validation, numeric bounds, URL policy, cryptographic key
admission, or trusted issuer configuration. A clock port may report dynamic
health, but every operation requires its sampled `healthy` value to be `true`.
Keep the runtime checks in
the execution path.

To check the included ESM and CommonJS fixtures, run the pinned workspace compiler
from the repository root:

```sh
npm run test:types
```

## Public API

The root export provides `createAgentKey`, `createWebCryptoAgentKey`,
`createRequestProofClient`, `createAgentClient`, `createProtectedRequestSigner`,
`createProtectedResourceClient`, `AgentError`, and `ResourceInvocationError`. The same factories are available through the documented
subpaths. ESM imports and synchronous CommonJS `require` are tested on Node 22.

## Hardware-backed key

The SDK accepts only a public P-256 JWK and an asynchronous signing port. Keep
the private key in the hardware or platform keystore. The callback receives a
fresh copy and returns a 64-byte IEEE-P1363 ES256 signature.

```js executable
import { createAgentKey } from '@atum/agent';

export async function createHardwareBackedKey({ publicJwk, hardwareKey }) {
  return createAgentKey({
    publicJwk,
    timeoutMs: 3_000,
    sign: signingInput => hardwareKey.signEs256(signingInput),
  });
}
```

`createWebCryptoAgentKey` adapts a non-exportable P-256 signing `CryptoKey`.
Both constructors verify every returned signature against `publicJwk`.

## Fixed issuer configuration

Configuration is explicit. Do not derive endpoints or CA material from the
environment or from an authorization response.

```js executable
export function createAgentConfiguration({ registration, registeredClient, endpoints,
  issuerCaPem, key, clock }) {
  return {
    registration,
    client: registeredClient,
    endpoints,
    tls: { ca: issuerCaPem },
    key,
    clock,
    timeoutMs: 5_000,
    maxConcurrent: 4,
  };
}
```

`clock()` returns exact `{now_ms,uncertainty_ms,healthy}` data. The six endpoint
fields are fixed canonical HTTPS URLs at the registered issuer origin:
`options_url`, `verify_url`, `par_url`, `authorization_url`,
`device_authorization_url`, and `token_url`.

## Authorization code and refresh

The client keeps the PKCE verifier and state private. Present the returned URL
unchanged, then pass the complete registered callback URL to
`completeCallback`. Persist `authorization_details` beside the refresh token.

```js executable
import { createAgentClient } from '@atum/agent';

export async function authorizeAndRefreshWithCode({ config, request, authorizeOwner }) {
  const agent = await createAgentClient(config);
  try {
    const flow = await agent.beginAuthorizationCode(request);
    const callbackUrl = await authorizeOwner({
      authorizationUrl: flow.authorization_url,
      requestId: flow.request_id,
      expiresAtMs: flow.expires_at_ms,
    });
    const first = await flow.completeCallback(callbackUrl);
    const rotated = await agent.refresh({
      refresh_token: first.refresh_token,
      authorization_details: first.authorization_details,
    });
    return { first, rotated };
  } finally {
    await agent.close();
  }
}
```

Navigate promptly because PAR retrieval is short-lived. Callback completion and
refresh are one-shot when their outcome is ambiguous. Never retry a submitted
refresh token after connection loss or a malformed response.

## Device authorization

The device code remains closure-private. Show the returned verification URL and
user code, then await the single poll promise.

```js executable
import { createAgentClient } from '@atum/agent';

export async function authorizeWithDevice({ config, request, signal, presentToOwner }) {
  const agent = await createAgentClient(config);
  try {
    const flow = await agent.beginDeviceAuthorization(request);
    const polling = flow.poll({ signal });
    polling.catch(() => {});
    await presentToOwner({
      verificationUri: flow.verification_uri,
      verificationUriComplete: flow.verification_uri_complete,
      userCode: flow.user_code,
      requestId: flow.request_id,
      expiresAtMs: flow.expires_at_ms,
    });
    return await polling;
  } finally {
    await agent.close();
  }
}
```

Polling handles only authenticated `authorization_pending` and `slow_down` and
stops at the original expiry. `poll` is one-shot and requires a genuine
`AbortSignal`. Abort stops future HTTP and discards a late result, but cannot
retract a request already received by the issuer.

## Protected resource signing

The signer produces request material only. The host owns resource HTTP,
validates the nonce challenge, and passes the trusted nonce into `sign`.

```js executable
import { createProtectedRequestSigner } from '@atum/agent/resource-proof';

export async function signProtectedRequest({ key, registration, endpoint, clock,
  accessToken, context, actionRequest, obtainTrustedNonce }) {
  const signer = createProtectedRequestSigner({ key, registration, endpoint, clock });
  const challenge = await signer.signChallenge({
    access_token: accessToken,
    context,
    action_request: actionRequest,
  });
  const nonce = await obtainTrustedNonce(challenge);
  return signer.sign({
    access_token: accessToken,
    context,
    action_request: actionRequest,
    nonce,
  });
}
```

Both methods return frozen `{authorization,dpop,body,method,url}`. Keep the same
operation context and action body across the challenge continuation. Proof
verification still requires a resource verifier and independent admission.

## Safe failures and boundaries

Catch `AgentError` and branch on `code`: `invalid_request`, `invalid_proof`,
`access_denied`, `invalid_grant`, `expired_token`, or
`temporarily_unavailable`. Messages intentionally contain no provider body,
token, proof, key callback error, or owner reason.

Do not log authorization or callback URLs, device codes, tokens, DPoP proofs,
nonces, cookies, or private key material. The SDK does not persist flow state.

Implemented and verified: trusted-CA request proof, PAR/S256 code and Device
flows, one exact token DPoP nonce continuation, refresh rotation, revoked-grant
`invalid_grant`, protected request signing, and actual owner/issuer browser
acceptance.

`createProtectedResourceClient` is the public sandbox client for the fixed
`POST /v1/atum/operations` profile. It takes the same protected-request input,
performs one nonce challenge and at most one fresh-proof continuation, then returns
only the closed operation result. The default TLS trust is Node's default CA configuration;
use exact `{ tls: { ca } }` only for a private CA. It never retries a business
operation, refreshes a token, assigns an operation ID, exposes raw responses, or
offers status/read.

```js
import { createProtectedResourceClient } from '@atum/agent/resource-client';

export async function invokeSandboxOperation({ registration, key, endpoint, clock,
  sandboxCaPem, accessToken, context, actionRequest }) {
  const resource = createProtectedResourceClient({ registration, key, endpoint,
    clock, tls: { ca: sandboxCaPem }, timeoutMs: 5000 });
  try {
    return await resource.invoke({ access_token: accessToken, context, action_request: actionRequest });
  } finally { await resource.close(); }
}
```

The process-local client fences every attempted `operation_id`, including an
unknown/timeout outcome, until `close()`. The host must persist original operation
state and recover it through its durable resource protocol; a timeout cannot cancel
an already received request. This is a sandbox integration only: it does not
authorize real-money activity or establish physical/native evidence.

Not provided: discovery, proxies, cookies, live status reads, durable flow
persistence, automatic retry after ambiguous I/O, or production deployment.
See the [joined result](../../../docs/status.md).

## Verification

```sh
node test/documentation.test.mjs
npm test
```

The documentation test imports and calls every marked example, checks ESM and
CommonJS exports, runs the code, Device, and refresh examples against a local
trusted-CA TLS fixture, and exercises protected-request signing. The joined browser harness is described in the
[OAuth service guide](../../../docs/status.md).
