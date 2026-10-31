# Durable DPoP nonce/replay adapter — component 0.1.0-draft.7

Implements the REQUIRED replayStore port of verification component draft.3; no wire change
to that proof profile or draft.2 context. Internal PostgreSQL16+ storage, no auto migration,
routes, background daemon, shared database access or production activation. Private package.
The user already authorized complete parallel SDK implementation; these are engineering
choices within that scope. Owner pending binding/consent and online admission remain separate.

## Public interface

Synchronous `createPostgresReplayStore({pool,clock,binding})` returns frozen methods
`issueNonce({agent_key_thumbprint})`, `consume(input)`, `prune({limit})`.
Export `ReplayStoreError` with safe code `temporarily_unavailable`; never include SQL,
connection details, nonce, JWT or unsanitized cause in errors. Invalid config/input TypeError.

Config EXACT fields. pool is a trusted node-postgres Pool-compatible object with .connect(callback);
clock the trusted measured function from draft.3; binding EXACT {issuer,audience,endpoint_url}.
Issuer/audience ASCII draft.2 party alphabet1..256. endpoint_url canonical HTTPS, no query,
fragment, credentials, percent escapes or normalized differences, length1..2048. Capture
functions and copied/frozen binding before any await; never accept caller-selected binding.
Adapter does not end the supplied pool or create it from environment variables.

Input snapshots synchronously validated before first await. Objects plain, no unknown keys.
Thumbprint and nonce canonical unpadded base64url32bytes; proof_jti16..128 base64url characters;
intent_hash `sha256:` +64 lowercasehex. Time values safe integer UTC milliseconds0..8.64e15.
Input strings checked length before scanning/decoding. No normalization of signed identifiers.

`clock()` EXACT {now_ms,uncertainty_ms,healthy}; healthy===true, safe integer uncertainty0..1000,
now within JS Date range including uncertainty. Exceptions/unhealthy/overflow -> unavailable.
Snapshot lower=max(0,now-uncertainty),upper=now+uncertainty. Recheck after waits and before
COMMIT and after its response; local now must not move backwards within a call. A production measured/staleness
monitor remains a dependency; DB time is NOT evidence of clock health.

## Issue

Generate nonce with node:crypto randomBytes(32), canonical base64url. Never inject a caller nonce.
Expiry is initial now_ms+30000 (checked range); require expiry>clock.upper at return/commit.
Persist only SHA256(`atum.dpop.nonce.v1\n` + ASCII nonce) as lowercase hex, not plaintext nonce.
Store issuer/audience/key/endpoint and immutable issued_at_ms/expires_at_ms. Return frozen
{nonce,expires_at_ms} only after known successful commit. Do not renew an existing nonce;
hash collision/DB errors -> unavailable. This is an internal issuance method: the eventual
HTTP/auth adapter must rate-limit and bind a challenge to the intended agent key/endpoint.
Calling issueNonce alone creates no authority or evidence.

## Consume

Input EXACT draft.3 fields {issuer,audience,agent_key_thumbprint,proof_jti,nonce,endpoint_url,
intent_hash,now_upper_bound_ms,replay_expires_at_ms}. Malformed -> TypeError; well-formed
binding unequal to configured issuer/audience/endpoint -> false without touching storage.
replay_expires_at_ms=proof_iat*1000+61000 from the trusted verifier, so require >=61000,
(expiry-61000)%1000===0, derived iat<=input now_upper, input now_upper<=expiry-1000.
Stale/future windows -> false. This adapter is not a cryptographic verifier; only a trusted
in-process verifier may call it after signatures/bindings have passed.

On ONE checked-out client and ONE transaction:
1. SELECT the hash-indexed nonce FOR UPDATE (including used row if present).
2. Re-read measured clock after lock; effective upper=max(input upper, own clock upper).
3. Unknown/consumed/expired nonce, wrong key/binding, or proof outside derived time window
   -> ROLLBACK false, without consuming anything. Nonce expiry comparison is strict `>`.
4. INSERT proof marker ON CONFLICT DO NOTHING, unique by
   (issuer,audience,agent_key_thumbprint,proof_jti), excluding nonce/endpoint/intent/operation.
   Existing marker -> ROLLBACK false, preserving an otherwise valid new nonce.
5. Mark nonce consumed. Re-read clock after SQL waits, before COMMIT, and recheck both nonce
   expiry and proof freshness using maximum upper bound. If invalid, ROLLBACK both changes.
6. Require nonce UPDATE rowCount===1 (zero-row update is not success). Only known successful
   COMMIT followed by a healthy, fresh clock check returns literal true. Partial commit / timeout / unavailable
   -> throw safe unavailable; never retry and silently report success after ambiguous outcome.
   If post-COMMIT time is invalid, changes may already be durable: return unavailable,
   never claim rollback of a known committed change. Issue and prune also recheck clock after
   commit; issue returns unavailable if its nonce has already expired.

Identical proof across workers -> <=1 success. Same jti with two nonces -> <=1 success,
losing nonce remains usable with a NEW jti. Same nonce with two jtis -> <=1 success.
Persistence must survive client/process reconnect; intent changes never reset replay identity.

## Additive authenticated issuance (unreleased continuation)

`@atum/replay-postgres/nonce-challenge` exports
`createPostgresNonceChallengeStore({pool,clock,binding,maxActiveNoncesPerKey})`.
The required cap is integer 1..64. It returns frozen `issueVerifiedNonce(fact,
{deadlineAt})`; deadlineAt is absolute performance.now() time with positive
remaining budget at most 5000ms. Host captures the same deadline before crypto.
This internal port receives only the trusted challenge verifier's exact fact:

```
nonce_issue_only:true, issuer, audience, endpoint_url, agent_key_thumbprint,
proof_jti, intent_hash, token_expires_at_ms, proof_iat_ms,
replay_expires_at_ms, verified_now_ms, verified_upper_bound_ms
```

Facts/options are descriptor snapshots before await; accessors/extra/symbol
fields reject. Match the configured binding, canonical JKT/hash/JTI and safe
times. Proof iat is in integer seconds expressed as milliseconds; replay expiry
equals iat+61000. Verification upper must be now..now+1000; token is unexpired
and proof fresh under that upper. Invalid input/config is safe TypeError.

Closed outcomes: frozen `{status:'issued',nonce,expires_at_ms}`,
`{status:'replayed'}` or `{status:'rate_limited'}`. Storage/clock/budget ambiguity
throws the existing public ReplayStoreError. These results are not authority.

In one callback-acquired transaction, recheck measured time and take
pg_advisory_xact_lock on the signed big-endian first8 SHA256 bytes of
`atum.dpop.nonce.capacity.v1\n` + canonical JSON `[issuer,audience,JKT]`.
All SQL predicates use full tuple strings; lock hash collision only serializes.
Count consumed_at_ms IS NULL and expires_at_ms > current healthy lower for that
issuer/audience/JKT across endpoints/tokens. No existing nonce row is locked or
evicted. At cap roll back rate_limited. Otherwise insert initial proof JTI/actual
intent under existing proofs uniqueness; conflict rolls back replayed. Insert
random32 nonce under the existing hash domain, expiry min(initial.now+30000,
token_expiry). Partial index `002_nonce_challenge_capacity.sql` supports counting.

After waits and before/after COMMIT, require nonregressing healthy now, maximum
verified/current upper, live token and nonce, proof iat<=upper<=iat+60000.
Optional internal transaction deadline caps acquisition/query/COMMIT waits;
legacy replay calls omit it and retain their previous per-stage bounds. Timeout
destroys uncertain clients without queueing rollback behind outstanding SQL.
A late successful COMMIT may be durable; unavailable never promises rollback.
No automatic retry, new replay table or fresh business deadline is introduced.

The future host selects the nonce-omitted path before complete verification and
returns standard401 use_dpop_nonce. A present invalid nonce cannot fall back.
Host raw framing/rate/route wiring and joint MERX E2E remain separate; internal
legacy issueNonce must not bypass public issuance serialization/capacity.

## Transactions and operational bounds

Explicit BEGIN ISOLATION LEVEL READ COMMITTED, schema-qualified parameterized queries,
SET LOCAL synchronous_commit=on; lock_timeout=1000ms, statement_timeout=3000ms,
idle_in_transaction_session_timeout=5000ms. Never use pool.query across a transaction.
Bound the caller's pool-acquisition wait to1000ms with late-client destruction. This timeout
cannot cancel the host's pending pool.connect request. A positive finite host
connectionTimeoutMillis must bound/remove queued acquisitions; finite pool size, bounded
inbound concurrency and an error-event handler are also required. Late-client destruction
alone does not bound a full pool's waiting queue. Bound each client query promise
to4000ms and destroy uncertain connections; clear every timer. Best-effort bounded rollback
on exceptions; release normally only if transaction state is known clean. Component-owned
timers are cleared after a completed call; pending host acquisition remains governed by the
host timeout above. COMMIT response loss is unavailable even if DB committed.
Pool credentials/TLS/error-event handlers and resource admission are host responsibilities.

Acquire using the node-postgres-compatible connect(callback) API and install a scoped client
error observer synchronously inside its success callback, before driver control resumes.
Promise-only connect wrappers are unsupported: consecutive protocol messages can otherwise
emit a fatal client error before a Promise continuation installs a listener. The client must
provide query/release/on/removeListener; wrappers must forward the event methods. Latch faults
through queries, query gaps and COMMIT, reject with safe unavailable and destroy the client.
Clear query timers/subscriptions when the fault settles them. Release before removing the
component listener so the pool has restored its idle listener; preserve other listeners.

## Schema and cleanup

Explicit migration `migrations/001_nonce_replay.sql` creates schema `atum_request_proofs`
and tables `nonces`, `proofs`. Do not use IF NOT EXISTS to mask partial/incompatible migrations.
Use TEXT with explicit bounds or VARCHAR with C collation for identifier comparisons; bigint
timestamps constrained0..8.64e15; no floating point or Date coercion. Proof primary key is
above; nonce primary key nonce_hash. Nonces have nullable consumed_at_ms. Proofs store
intent_hash,first_seen_ms,expires_at_ms for bounded audit/retention. Expiry indexes.

`prune({limit})`: integer1..1000, EXACT input. Bounded cleanup of <=limit rows PER table,
only expires_at_ms < own clock LOWER bound, using locked candidates FOR UPDATE SKIP LOCKED
in a transaction. Scope to configured issuer/audience; nonces also configured endpoint.
Proof replay identity intentionally spans endpoints in the audience. No request-supplied time.
Return frozen {nonces_deleted,proofs_deleted}. Do not enable a scheduled job in this increment.
Cleanup must not delete active markers/nonces; expired marker removal is safe because the
verifier rejects proofs outside their original freshness window. Failed clock -> no cleanup.

## Evidence and boundaries

Unit/fault tests: exact inputs, bounds, wrong binding, injected failures, unavailable clock,
late acquisition, query timeout/rollback/release and snapshots. Integration tests use a NEW
Unix-socket-only PostgreSQL cluster, host auth reject, no inherited DATABASE_URL/PG* target.
Cover successful consume, all nonce bindings, expiry equality, all3 concurrency races,
no partial consume on duplicate jti, reopen/restart, transactional rollback, lock timeout,
clock advance during locks and bounded prune preserving live rows. Connect the real verifier
to the real adapter using freshly generated synthetic signed requests (no real credentials).

Driver for tests: exact pg8.20.0 matching MERX, not claimed latest. Runtime accepts injected
Pool, so callers can control their compatible driver. References:
[node-postgres transactions](https://node-postgres.com/features/transactions),
[Pool release/connection handling](https://node-postgres.com/apis/pool),
[PostgreSQL16 row locks](https://www.postgresql.org/docs/16/sql-select.html),
[unique insert semantics](https://www.postgresql.org/docs/16/sql-insert.html).
