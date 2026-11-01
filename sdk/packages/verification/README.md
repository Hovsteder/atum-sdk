# ATUM verification component

Public developer-preview package `@atum/verification@0.1.0-rc.3`, Node >=22.12.
This is the protected-request part of G0, consuming the unchanged draft.2 context contract.
It verifies issuer-signed access tokens, the agent's DPoP proof and the complete operation
context. It returns `requires_admission: true`; it does not issue an execution permission.

## Public hosting helpers

`@atum/verification/clock` provides `ObservedSystemClock`, a local-chronyd observer, an atomic observation writer, and the `atum-clock` executable. It does not set the system clock and it does not claim cryptographic NTP trust. `@atum/verification/node-http` provides `createProtectedHttpHandler`, which owns raw Node HTTP framing, nonce challenge and current-authorization verification before calling `onAuthorized(current_permission)`. The callback remains responsible for resource acceptance, quota and result semantics. See `docs/quickstart.md` and `docs/node-hosting.md` in the SDK repository.

## Contract and trusted inputs

[PROFILE.md](PROFILE.md) is the exact candidate interface, field, error, timing and replay
contract. It fixes RS256 issuer tokens and ES256/P-256 agent proofs using jose 6.2.14.
`atum_intent_hash` is an explicit extension of the DPoP proof: standard DPoP alone does not
bind the request body. The full context hash is still the draft.2 hash; MERX action bytes
and the quota/operation identities are unchanged.

`createVerifier` requires a trusted resource registration, public issuer keys, a registered
HTTPS POST endpoint, a measured clock adapter and an atomic replay/nonce store. There is no
remote key discovery, default clock, optional replay check or production memory fallback.
The HTTP adapter must reject duplicate headers and impose body limits before buffering.
This component also checks its own limits before copying inputs. Its returned frozen result
must be sent to authoritative admission, which checks live grant/revocation, permitted
action, owner/account binding and the applicable evidence policy. Do not treat the result
as an admission decision or pass agent-supplied copies of it across a trust boundary.

## Run isolated tests

From this directory:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm test
```

The bundled `test/fixtures/proof-vectors.json` has 48 fixed synthetic signed cases, one valid
and 47 negative. Each case supplies the exact request, expected outcome, fixture nonce state
and expected number of replay-store calls. Use the included historical test clock. Public
test keys are included; private keys were generated temporarily and never saved.
The test suite also checks concurrency, clock movement, parser limits, configuration/request
snapshots and algorithm confusion. Some environments display file-level counts for
`node --test`; `node test/FILE.test.mjs` prints the individual cases.

Independent signature check, with Python `cryptography` installed in an isolated environment:

```sh
python tools/check-signatures.py
```

It checks 96 signature expectations using a separate implementation, and checks the positive
context/action hashes, key thumbprint and token hash against the Python draft.2 reference.
It is not an independent implementation of the complete acceptance policy.

For a *new unpublished* fixture set, use `node tools/generate-signed-vectors.mjs NEW_PATH`.
The tool refuses to overwrite files. Regeneration uses fresh ephemeral keys and produces
different bytes; do not regenerate a published release in place.

## Integration still required

The replay store in these tests is a fixture only. The separate `@atum/replay-postgres`
component implements the persistent adapter. The production integration must atomically
validate and consume issued, bound, unexpired nonces and insert proof replay identities,
persist across restarts and multiple workers, and fail unavailable on backend errors.
The clock bound is a candidate parameter, still subject to shared clock-health agreement.

The private issuer and owner services have separate hosting and lifecycle requirements. This package alone cannot create consent or establish physical phone history. See [release status](../../../docs/status.md) for local integration evidence and public hosting availability.

## Signed authority component

The separate `@atum/verification/authority` export verifies pinned grant snapshots and
immutable admission assertions. See `../../authority/CONTRACT.md` and `README.md`.
The request-proof verifier remains proof-only; these distinct results must not be cast
into one another. The resource client supplies explicit mTLS or scoped-service-credential HTTPS transport. Current authorization composes proof and live signed authority checks.

## Neutral service-action profile

`@atum/verification/service-profile` exports the generic
`atum.service-actions.v1-draft.1` descriptor helpers. A descriptor contains a
sorted finite `actions` list and its sorted `account_required_actions` subset;
its canonical UTF-8 JSON SHA-256 is the registration's profile hash. Every
verifier/authority factory receives that descriptor from immutable trusted
configuration beside the registration. Request payloads never select or modify it.

Neutral actions are exact `{action,parameters}` objects. The action must be in
the descriptor and is at most 128 characters. Parameters use canonical JSON with printable ASCII object keys,
Unicode-scalar string values, safe integers, depth at most 8, and at most 16,384
canonical UTF-8 bytes. Floats, negative zero, unpaired surrogates and unknown
permission fields fail closed. Sparse arrays and arrays with custom or symbol
properties also fail closed. A neutral permission is exactly `{action}`; it
does not express or enforce opaque business predicates. The generic action hash
uses `atum.service.action.v1\n`. Proof verification still returns no authority,
and signed authority verification still does not execute or validate a service's
business result.

The fixed MERX implementations remain available through the old
`resource-profiles` import and the explicit `@atum/verification/merx-compat`
facade. Their hashes, domains and canonical bytes are unchanged.

## Fresh current authorization

`@atum/verification/current-authorization` exports
`createCurrentAuthorizationVerifier`. The factory receives one immutable
registration/descriptor, token issuer keys, atomic replay store, pinned authority
keys and explicit mTLS or scoped-service-credential HTTPS transport settings. `verifyCurrent(protectedRequest)` validates and
consumes the request proof, then fetches a fresh snapshot and makes one fresh
admission request. It verifies both signed facts against the exact context,
action, client and intent. It never retries or calls historical retrieval after
an ambiguous admission response.

The frozen result has `authorization_effect:'current_permission'` and
`requires_resource_acceptance:true`. It exposes the scoped subject, agent key,
context and action, original permissions and `grant_limit`, proof/admission IDs,
evaluated clock uncertainty, and every relevant expiry. `grant_limit` is the
owner-approved original cap, not remaining usage. The resource must atomically
accept/consume it and provide operation idempotency before doing work. Existing
`verifyAdmission(...,{mode:'inspect'})` remains the separate historical API and
never yields current permission. See the independent
[calendar resource example](../../examples/calendar-resource/README.md).

## Registered Energy profile candidate

`@atum/verification/resource-profiles` exports immutable `MERX_SANDBOX_V1`
and `MERX_ENERGY_V1` built-ins. The latter is the reviewed
`merx.energy-purchase.v1-draft.1` production-environment registration with
descriptor hash `sha256:e1c5106dc710ce0ba3d846f3cb376358eb858c35adfbac906f0ff58f3a6451fa`.
The runtime descriptor bytes are package-owned; matching canonical JSON and
Node/Python known answers are in `../../protocol/resource-profiles/`. Unknown
version/hash/environment tuples fail closed, and historical sandbox bytes stay
unchanged.

The Energy action validates the full TRON Base58Check checksum, exact UUIDv4,
supported term, provider, quote deadline, and canonical unsigned decimal SUN
strings through `Number.MAX_SAFE_INTEGER`. Its single permission is the exact
`{action,parameters}` request, with `grant_limit: 1` and grant expiry no later
than the quote. This is registry, consent, token and proof support; it does not
mount a provider adapter, reserve money, report delivery, or authorize live spend.

## Nonce-omitted challenge verifier

The nonce-challenge package subpath exports createNonceChallengeVerifier with
trusted registration, issuer keys, endpoint and measured clock. It is an
additive cryptographic preparation port for the same-protected-POST DPoP
nonce challenge. It does not mount HTTP, create a nonce, call replay storage,
contact admission, reserve quota, or execute an operation.

verifyNonceChallengeRequest accepts the same bounded normalized request shape as
the complete verifier, but only an exactly nonce-omitted DPoP payload. Its
host-captured deadlineAt uses performance.now(), must have positive remaining
budget no greater than five seconds, and is checked after every awaited
cryptographic operation. Malformed or present nonce fields never fall back into
this path.

Its deeply frozen result has only nonce_issue_only, issuer/audience, configured
endpoint URL, agent-key thumbprint, proof JTI, intent hash, token/proof/replay
times, and verified clock bounds. It contains no token, context, replay success,
admission or execution authority. A later trusted store/host layer may use the
fact to persist and emit a 401 challenge. The existing complete-proof API still
requires its original nonce and consumes the configured replay-store port.

## Authenticated resource client

`@atum/verification/resource-client` exports `createResourceClient` and
`ResourceTransportError`. It uses a configured HTTPS origin and explicit CA, client
certificate and private key for mTLS to call the authority resource's snapshot, admission,
and historical-retrieve endpoints. It validates the complete bound context and action before
network I/O, has no retries, and returns only the original compact assertion bytes.

`baseUrl` must be the exact canonical HTTPS origin string, with at most its single trailing
`/`; paths that URL parsing could normalize, credentials, query/fragment text, whitespace and
backslashes are rejected. Registration `issuer` and `audience` must be strings, and the CA,
certificate and private key are parsed when the client is constructed. Invalid local TLS
material therefore fails as `TypeError('invalid config')` before a request or deadline timer
exists.

Each request deadline begins before it enters the HTTPS transport and covers client capacity,
connection, TLS, headers and body. On expiry the returned operation fails closed and its
request is destroyed, but its concurrency slot remains held until the response completes or
the request closes; a follow-up call cannot be queued in the HTTPS agent during that interval.
`close()` immediately rejects future operations, destroys queued or active transport work, and
resolves only after all work that had acquired a slot has completed or closed. Callers should
await `close()` before tearing down their process or local test server.

TLS is transport authentication, not admission authority: callers must pass every returned
assertion through the authority verifier before acting. After a timeout or connection loss,
call `retrieve` with the same immutable context and client ID to recover historical state;
do not infer rollback or create a fresh decision. Only `retrieve`'s authenticated
`404/not_found` is distinguishable from transport failure. All other failures are safe
`ResourceTransportError` values and must fail closed.

```js
import { createResourceClient, ResourceTransportError } from '@atum/verification/resource-client';

const authority = createResourceClient({
  baseUrl: 'https://authority.example.test:8443',
  registration, // trusted, fixed resource registration
  tls: { ca: caPem, cert: resourceCertificatePem, key: resourcePrivateKeyPem },
  timeoutMs: 8000,
  maxConcurrent: 4,
});
try {
  const assertion = await authority.snapshot({ context, action_request, client_id });
  // Verify this original assertion with @atum/verification/authority.
  // Transport success alone never permits reservation or execution.
} finally {
  await authority.close();
}
```

A MERX adapter translates its existing `actionRequest`/`clientId` to
`action_request`/`client_id`. Only a `ResourceTransportError` with code `not_found`
from explicit historical `retrieve` may map to MERX's null result. Do not use
a generic catch-to-null or silently retry admission. See the executable
[cross-language E2E](../../../docs/status.md) for actual signatures,
mTLS, separate service processes and database restart.

## Owner connector transport (opt-in development slice)

`@atum/verification/owner-connector-client` exports `createOwnerConnectorClient`
and `OwnerConnectorTransportError`. This separate mTLS role implements the six
AC-018 routes; a resource-client certificate has no implicit connector access.
It does not verify owner consent or make an account binding ready by itself.

```js
import { createOwnerConnectorClient } from '@atum/verification/owner-connector-client';
const connector = createOwnerConnectorClient({
  baseUrl: 'https://connector.example',
  registration: { issuer, audience, environment: 'sandbox', tenant_id, resource_id, quota_scope_id },
  tls: { ca, cert, key }, timeoutMs: 5000, maxConcurrent: 4,
});
try {
  const original = await connector.read({ flow_id });
  // Use the saved phase/material. Do not infer consent from transport success.
} finally { await connector.close(); }
```

Methods are `open`, `pair`, `reservation`, `confirmation`, `outcome`, `read`, and
`close`; exact request/response schemas are in
[AC-018](../../../docs/owner-connector.md).
The six-field registration is fixed configuration. No browser identity is sent
in headers; no callback URL, redirect or implicit environment fallback exists.
Every response is checked against the original flow/context and closed completed-
stage material shape, then copied and deeply frozen. The original statement
string is preserved byte-for-byte. Signature/clock/owner-state checks remain the
receiving component's responsibility.

Request/response bounds are 98,304/131,072 bytes; timeout at most 5 seconds and
concurrency at most 16. Capacity remains occupied until the socket actually
closes. A network error, malformed reply or timeout is `temporarily_unavailable`:
the effect may have committed. The client never retries mutations; recover with
an authenticated `read` and the original flow ID. Only an exact authenticated
error/status pair is a known server rejection. `close()` terminates outstanding
requests and waits for their close events.

Five focused real-mTLS tests cover all six paths, raw numeric-token bounds before JSON rounding, input snapshots, immutable
results, phase/context substitutions, malformed/duplicate/chunked/oversized/
truncated replies, deadlines and no-retry capacity. The Python listener has
separate real-socket checks. These are transport-component checks; actual
MERX/ATUM owner flow and PostgreSQL/browser acceptance remain in progress.
