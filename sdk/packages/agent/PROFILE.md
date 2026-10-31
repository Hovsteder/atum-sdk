# Registered ATUM Agent Profile

This is the integration contract for the developer-preview `@atum/agent` package. It
describes the implemented sandbox profile verified on Node.js 22.12 or newer.
It is not discovery metadata and does not define a new wire protocol.

## Host responsibilities

The host supplies a trusted registration, registered public-client record,
fixed issuer endpoints, issuer CA bundle, P-256 signing port, and measured
clock. Treat them as configuration. Never accept replacements from a callback,
token response, environment proxy, or arbitrary URL argument.

Install this preview through the repository workspace. npm registry publication
and production deployment are separate milestones.

## Exact configuration

```js executable
export function registeredAgentConfig({ registration, client, endpoints, issuerCaPem,
  key, clock }) {
  return {
    registration,
    client,
    endpoints,
    tls: { ca: issuerCaPem },
    key,
    clock,
    timeoutMs: 5_000,
    maxConcurrent: 4,
  };
}
```

The exact registration fields are:

| Field | Implemented constraint |
| --- | --- |
| `issuer` | Registered canonical HTTPS issuer identity |
| `audience` | Registered resource audience |
| `environment` | Exact `sandbox` |
| `tenant_id` | Registered tenant identifier |
| `resource_id` | Registered resource identifier |
| `quota_scope_id` | Registered quota scope |
| `operation_namespace` | Registered operation namespace |
| `resource_profile_version` | Exact `v1-draft.1` |
| `resource_profile_hash` | Exact `sha256:dc6f6409a47da2a97ea7b4ace313985d7fcd4c6b8459a59ea06b014de304a175` |
| `policy_version` | Registered policy identifier |
| `account_required_actions` | Unique allowed actions |

The client record is exact
`{client_id,flows,redirect_uris,permissions,max_grant_limit,max_grant_lifetime_ms}`.
Implemented flows are `authorization_code` and `device_code`. Implemented
actions are `prices.read`, `order.preview`, and `sandbox.execute`; registration
and client policy decide which are available.

`client.permissions` is the unique string allowlist. A request instead carries
one to three unique permission objects from that allowlist. `prices.read` is
exactly `{action:'prices.read'}`. `order.preview` and `sandbox.execute` are
exactly `{action,max_amount,max_duration,max_price_sun}`, where `max_amount` is
an integer from 1 through 1,000,000,000, `max_duration` is an integer from 1
through 2,592,000, and `max_price_sun` is either `null` or an integer from 1
through 1,000,000,000,000.

The endpoint record contains `options_url`, `verify_url`, `par_url`,
`authorization_url`, `device_authorization_url`, and `token_url`. Each is
canonical HTTPS at the issuer origin, with no credentials, query, or fragment.
TLS uses only the supplied CA bundle and strict server identity. No redirects,
environment proxy, cookies, or environment CA settings are used.

The clock returns a fresh exact `{now_ms,uncertainty_ms,healthy}` record. Time is
an integer Unix millisecond value, never moves backward during the client
lifetime, and has at most 1,000 ms uncertainty. `healthy` must be `true`.

## Signing key port

```js executable
import { createAgentKey } from '@atum/agent/key';

export async function agentKeyFromSigningPort({ publicJwk, signingPort }) {
  return createAgentKey({
    publicJwk,
    timeoutMs: 5_000,
    sign: bytes => signingPort.signEs256IeeeP1363(bytes),
  });
}
```

`publicJwk` is exactly `{kty:'EC',crv:'P-256',x,y}` with canonical 32-byte
coordinates. The private key never enters SDK configuration. Each callback gets
a detached byte copy and returns exactly 64 detached signature bytes. The SDK
captures and locally verifies every signature.

## Request preparation wire

`createRequestProofClient(config)` sends exactly two JSON POSTs. `options_url`
receives the registered flow, client, resource, normalized RAR, optional code
metadata, and public agent JWK. `verify_url` receives the returned challenge ID
and signed `atum-oauth-request+jwt` proof.

```js executable
import { createRequestProofClient } from '@atum/agent/request-proof';

export async function prepareRegisteredRequest({ config, input }) {
  const requests = createRequestProofClient(config);
  try {
    return await requests.prepare(input);
  } finally {
    await requests.close();
  }
}
```

Authorization-code input is exact
`{flow:'authorization_code',permissions,grant_limit,grant_expires_at_ms,redirect_uri,code_challenge,state}`.
Device input omits the last three fields and uses `flow:'device_code'`.
Permissions are unique and limited to three. The frozen result is
`{request,request_hash,atum_request,expires_at_ms}`. `atum_request` is secret
native request material and must not be logged or stored in a browser.

## Authorization code, token, and refresh

`createAgentClient(config)` owns request preparation, PKCE verifier, state, PAR,
token DPoP, and the single permitted token nonce continuation.

The high-level `beginAuthorizationCode` input is exactly
`{permissions,grant_limit,grant_expires_at_ms,redirect_uri}`. `grant_limit` must
not exceed the registered client maximum. The grant expiry must be in the future
and within the registered `max_grant_lifetime_ms`; `redirect_uri` must be one of
the registered client redirects. PKCE challenge and state are generated inside
the client and are not caller fields.

```js executable
import { createAgentClient } from '@atum/agent/client';

export async function codeGrantWithRotation({ config, request, authorizeOwner }) {
  const agent = await createAgentClient(config);
  try {
    const flow = await agent.beginAuthorizationCode(request);
    const callbackUrl = await authorizeOwner(flow.authorization_url);
    const tokens = await flow.completeCallback(callbackUrl);
    const rotated = await agent.refresh({
      refresh_token: tokens.refresh_token,
      authorization_details: tokens.authorization_details,
    });
    return { tokens, rotated };
  } finally {
    await agent.close();
  }
}
```

Open `authorization_url` without editing its query. Pass the complete registered
callback URL to `completeCallback`. Scheme, host, port, path, state, and issuer
must match. Duplicate or extra fields, credentials, fragments, and malformed
code shapes fail before token I/O. A valid-shaped substituted code reaches the
issuer and must be rejected there.

The provider requires one exact `400 use_dpop_nonce` challenge. The SDK permits
one continuation with a fresh JTI under the same five-second budget. Any second
challenge or ambiguous result is terminal. Refresh requires both the token and
persisted exact `authorization_details`; success must rotate the token. After an
ambiguous refresh, discard the submitted token and authorize again.

## Device authorization

```js executable
import { createAgentClient } from '@atum/agent/client';

export async function deviceGrant({ config, request, signal, display }) {
  const agent = await createAgentClient(config);
  try {
    const flow = await agent.beginDeviceAuthorization(request);
    const polling = flow.poll({ signal });
    polling.catch(() => {});
    await display({
      uri: flow.verification_uri,
      completeUri: flow.verification_uri_complete,
      userCode: flow.user_code,
      expiresAtMs: flow.expires_at_ms,
    });
    return await polling;
  } finally {
    await agent.close();
  }
}
```

Device input is exact `{permissions,grant_limit,grant_expires_at_ms}`. The wire
response has exactly `device_code`, `user_code`, `verification_uri`,
`verification_uri_complete`, and `expires_in`, plus optional `interval`.
The native profile accepts a consonant code shaped `BCDF-GHJK`, expiry 1 through
300 seconds, and interval 1 through 300 seconds. Missing interval means five.

The public handle omits `device_code`. `poll({signal})` is one-shot, waits before
the first request, keeps the interval after `authorization_pending`, adds five
seconds after each `slow_down`, and stops at the original conservative expiry.

## Protected resource proof

The signer requires the same key and registration plus one fixed exact
`{method:'POST',url}` endpoint. It validates the context, action request, and
`context.agent_key_thumbprint` against configuration.

```js executable
import { createProtectedRequestSigner } from '@atum/agent/resource-proof';

export async function protectedRequestWithNonce({ key, registration, endpoint, clock,
  accessToken, context, actionRequest, exchangeChallenge }) {
  const signer = createProtectedRequestSigner({ key, registration, endpoint, clock });
  const challengeRequest = await signer.signChallenge({
    access_token: accessToken,
    context,
    action_request: actionRequest,
  });
  const trustedNonce = await exchangeChallenge(challengeRequest);
  const protectedRequest = await signer.sign({
    access_token: accessToken,
    context,
    action_request: actionRequest,
    nonce: trustedNonce,
  });
  return { challengeRequest, protectedRequest };
}
```

The access token is bounded opaque ASCII at this layer. `signChallenge` omits
only the nonce. Invalid nonce input to `sign` never falls back to a challenge.
Keep token, context, operation ID, and action body identical across the
continuation. Returned material is frozen
`{authorization,dpop,body,method,url}`.

The host sends the request. Resource HTTP, challenge parsing, durable replay,
token verification, authority admission, business execution, and recovery are
outside this public package.

## Failure contract

| `AgentError.code` | Host action |
| --- | --- |
| `invalid_request` | Fix local input; do not send it again unchanged |
| `invalid_proof` | Stop and inspect the configured signing port privately |
| `access_denied` | Record owner denial without provider description |
| `invalid_grant` | Discard the artifact and authorize again |
| `expired_token` | Start a new authorization if still required |
| `temporarily_unavailable` | Treat the outcome as unknown; do not retry an ambiguous token artifact |

Messages are generic and omit upstream bodies, signer exceptions, owner reasons,
tokens, proofs, and secrets. Configuration errors throw `TypeError` before I/O.

## Operational limits and exclusions

- Operation timeout: 1 through 5,000 ms; default 5,000.
- Client concurrency: 1 through 16; default 4.
- Issuer JSON is closed and at most 32 KiB.
- No redirects, cookies, proxies, compression, arbitrary URLs, or ambiguous-I/O
  retry.
- Flow secrets are process-local unless the host stores required artifacts.
- Always call `close()` in `finally`.

Verified scope includes trusted-CA loopback TLS, actual Chromium owner/issuer
code and Device flows, rotating refresh, revocation, durable replay, authority
admission, and public protected-request verifier compatibility.

It does not include public resource HTTP, resource nonce transport, live status,
restart-safe flow persistence, MERX execution, native sensor evidence,
production clock, CA operations, or deployment readiness.

Run the executable documentation contract with:

```sh
node test/documentation.test.mjs
```
