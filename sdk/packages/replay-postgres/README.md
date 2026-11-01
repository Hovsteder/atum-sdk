# ATUM persistent nonce and replay adapter

Public developer-preview package `@atum/replay-postgres@0.1.0-rc.3`, Node >=22.12,
PostgreSQL 16+. Implements the `replayStore` port of `@atum/verification` without
changing the draft.2 context or `atum-dpop-v1-draft.1` wire profile.

A request must consume one issued nonce and register one proof identity in the
same transaction. Concurrent workers, a new connection, or a restart cannot make
that proof usable again. Only the nonce hash is persisted. This component does
not grant permission to perform an operation; online admission remains required.

## Host integration

1. Provision a separate database/role for the intended environment. Apply
   `migrations/001_nonce_replay.sql` explicitly, once, in your migration system.
   Importing this package never runs a migration or reads connection environment variables.
2. Supply a node-postgres-compatible pool, with host-managed TLS, credentials,
   a positive finite `connectionTimeoutMillis`, finite pool size and an error listener.
   Bound inbound concurrency separately. The component neither creates nor ends the pool.
3. Supply the trusted measured clock adapter and the registered resource binding.
   There is no default `Date.now()` clock: an unmeasured or unhealthy clock must fail closed.
4. Pass the store to the complete proof verifier. Public nonce negotiation uses
   the separate authenticated issuance component below; legacy `issueNonce` is
   a trusted internal/test method and must not become an unbounded HTTP bypass.

The component's 1000ms acquisition timeout bounds its caller's wait, but cannot cancel
the host's pending `pool.connect()` request. A late-acquired client is destroyed. Until
then, the host pool must remove timed-out pending acquisitions using its own positive
`connectionTimeoutMillis`; pool size alone does not bound the waiting queue. These host
limits, inbound concurrency and challenge rate limits are required together. Choose their
values for the deployment; test settings are not production sizing recommendations.

The pool must implement node-postgres's `connect(callback)` handoff and return clients with
`query`, `release`, `on` and `removeListener`. Client error protection is installed inside
that callback, before it returns to the driver. A Promise-only wrapper can leave an unhandled
error window during handoff and is not a supported adapter. Any wrapper must forward event
methods to the same checked-out client. Pool-level error handling remains the host's duty.

```js
import { createPostgresReplayStore } from '@atum/replay-postgres';
import { createVerifier } from '@atum/verification';

// pool, measuredClock, endpoint, registration and issuerKeys are trusted host inputs.
const replayStore = createPostgresReplayStore({
  pool,
  clock: measuredClock,
  binding: {
    issuer: registration.issuer,
    audience: registration.audience,
    endpoint_url: endpoint.url,
  },
});
const verifier = await createVerifier({
  registration, issuerKeys, endpoint, clock: measuredClock, replayStore,
});
// Internal/test setup only; not the public HTTP challenge boundary.
const challenge = await replayStore.issueNonce({ agent_key_thumbprint: agentJkt });
// Call the verifier on the actual received request, never on an agent-supplied result.
const checked = await verifier.verifyProtectedRequest(receivedRequest);
// checked.requires_admission === true; obtain authoritative admission next.
```

`consume` is an internal verifier port, not an HTTP endpoint. Never expose it to
untrusted callers. `prune({limit: 100})` removes at most 100 expired rows per table
using the measured clock's lower bound. The host decides when to run it; no job
or background process is started by this package.

Nonce lifetime is 30 seconds. Proof replay identity spans endpoints within the
registered issuer/audience and does not include nonce, intent or operation ID.
Exact fields, timing rules, transaction limits and schema are in [PROFILE.md](PROFILE.md).

## Authenticated nonce negotiation component

The additive `@atum/replay-postgres/nonce-challenge` subpath implements atomic
issuance for a previously verified nonce-omitted DPoP request. The MERX protected
POST and actual Agent/TLS/sandbox composition now pass in the private
[joined milestone](../../../docs/status.md).
Five challenges produce no business changes and exact continuation replay is denied;
this acceptance does not publish a production service or a new package release.

Apply `migrations/002_nonce_challenge_capacity.sql` after migration 001 before
using this component. It adds a partial capacity index, without another table.
Importing either factory never applies migrations.

```js
import { createNonceChallengeVerifier } from '@atum/verification/nonce-challenge';
import { createPostgresNonceChallengeStore } from '@atum/replay-postgres/nonce-challenge';

const nonceVerifier = await createNonceChallengeVerifier({
  registration, issuerKeys, endpoint, clock: measuredClock,
});
const nonces = createPostgresNonceChallengeStore({
  pool, clock: measuredClock,
  binding: { issuer: registration.issuer, audience: registration.audience,
    endpoint_url: endpoint.url },
  maxActiveNoncesPerKey: 4, // example host policy, not a production default
});
// Capture once at the start of bounded host processing, not again after crypto.
const budget = { deadlineAt: performance.now() + 5000 };
const fact = await nonceVerifier.verifyNonceChallengeRequest(receivedRequest, budget);
const issued = await nonces.issueVerifiedNonce(fact, budget);
// status: issued | replayed | rate_limited. Only issued contains nonce/expiry.
// The host maps issued to HTTP 401 use_dpop_nonce, never operation acceptance.
```

Only the trusted verifier result may reach `issueVerifiedNonce`. It is not an
HTTP method and must not accept request-supplied facts or `nonce_issue_only` flags.
The initial proof's JTI and real intent hash are inserted in the same transaction
as the nonce; they share the complete verifier's replay identity. The continuation
must use a fresh JTI. Capacity counts possibly-live unused nonces across all tokens
and endpoints for issuer/audience/key, under a transaction advisory lock. It never
evicts another outstanding nonce. Legacy internal issuance must not be exposed as
a parallel path around this limit.

The required absolute monotonic deadline covers crypto and storage together when
passed as shown. It caps acquisition, each SQL wait and transaction completion.
Token/proof/nonce time checks use a healthy measured clock before and after SQL
and COMMIT; nonce expiry is capped by the access token. Lost/late COMMIT is
`ReplayStoreError`, even if the marker/nonce are already durable. The store never
retries. `replayed` or `rate_limited` creates no new nonce or replay marker.

The host must still enforce aggregate/IP rate and inbound capacity before crypto,
strict raw headers/body, and exact no-store challenge responses. A nonce proves
neither active authorization nor a live passport; full proof, current account
binding and online admission remain mandatory before an effect.

## Failure handling

Malformed internal input throws `TypeError`. Invalid, expired or replayed input
returns `false` from `consume`. Database failures and unhealthy clocks throw
`ReplayStoreError` with safe code `temporarily_unavailable`, without SQL or secrets.

A lost COMMIT response or expiry during COMMIT may leave a consumed nonce in the
database. The call still fails; it never invents a successful rollback. A retry
needs a fresh nonce and proof while preserving the operation ID and original
admission deadlines. The verification component rechecks token/proof validity
after storage returns as well. No backend failure permits an in-memory fallback.

Checked-out client errors produce the same controlled unavailable result. The component
latches errors across queries and COMMIT, clears its query timers, destroys a faulted client
and removes only its own listener after release. An error during COMMIT never proves rollback
or grants a retry deadline; the original operation and admission rules still apply.

## Verification

From this directory, install the pinned development dependencies with
`npm ci --ignore-scripts`, then run `npm test`.

`python3 tools/test-postgres.py` creates its own PostgreSQL 16 cluster under a new
`/tmp/atum-replay-pg-*` directory, listens only on its Unix socket, rejects host
connections, and ignores inherited database target variables. On Linux it needs
the PostgreSQL 16 tools; root execution uses the existing `postgres` OS account.
The harness removes its cluster only after confirming that it stopped.

The harness applies the schema, runs concurrency/rollback/clock tests and real
JWT+DPoP verifier tests, then restarts PostgreSQL between two separate Node
processes. It verifies that a used proof stays rejected and an unused nonce stays
usable once. No production database, credentials or real authority are involved.

## Remaining integration

MERX has accepted the draft.7 replay component and verified it with the corrected
draft.8 authority bundle. Its shared owner/signed-ledger client handoff fix was
independently verified; see the [SDK status](../../README.md) and
[closure record](../../../docs/status.md).
Pending owner binding, two-party confirmation and signed admission exist as
separately tested components; this package does not implement those protocols.

OAuth persistence, actual enrollment/consent, authenticated nonce/service transport,
production measured clock and full G0 acceptance remain open. Existing published
archives are unchanged. Current source documentation is not a replacement artifact.
