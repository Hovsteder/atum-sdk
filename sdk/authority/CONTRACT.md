# Signed grant and admission component — draft.8

Status: implementation specification, sandbox component, NOT frozen G0. Supplements
draft.2 context and draft.3/4 request proof/replay; does not replace their bytes.
Explicitly separate from the synthetic `would_accept` reference decision.

## Trust boundaries

- Public request proofs establish possession and bind an exact request. They do not
  supply permissions, grant quota, consent validity or evidence.
- An internal trusted provisioning seam accepts a grant only AFTER owner consent was
  independently verified. This increment implements no public grant-creation route,
  owner-enrollment shortcut or agent-supplied consent. No production service wiring.
- Evidence enters through a separate trusted evaluator seam. A phone's claimed boolean
  is not server-recomputed evidence. No classifier, physical-human score or threshold
  is invented here. Null evidence is explicit when registered sandbox policy permits it.
- ATUM checks its current account-binding ID/version; MERX must also check its own
  active binding and account. ATUM activation alone cannot activate MERX's database.
- Service assertions use pinned ES256 keys by role, distinct from RS256 access-token
  keys, agent keys and owner-confirmation keys. No discovery URLs from untrusted data.
- Signed snapshot supports reservation/policy checks. Only a new admission transaction
  checks current grant status and evidence before the original permit is committed.
- Retrieval is an authenticated resource-server INTERNAL seam. HTTP resource auth,
  public owner/agent GET proof profiles and OAuth issuer transport remain separate work.

## Registration and immutable grant

Use EXACT draft.2 registration and `validate_bound_intent` / `validateBoundIntent`.
`template` is EXACT context minus `operation_id`, `action`, `action_hash`.
All registration values and full context/hash rules remain unchanged.

Grant object (closed):

```
{ template, client_id, grant_expires_at_ms, grant_limit, permissions }
```

`client_id` uses draft.2 ID syntax. `grant_limit` integer 0..1,000,000,000 is an
explicit trusted per-grant sandbox-unit limit; no default. MERX's subject limit is
independently configured and remains shared across grants/keys/versions/namespaces.
Expiry is an integer millisecond timestamp 0..8,640,000,000,000,000, strictly in future
when creating a new grant.
Grant ID is immutable within (issuer, environment). Existing ID with changed version,
consent, scope, key, limits or template conflicts. An identical retry returns existing
state, including after expiry, revocation, or removal of its current account binding.
It does not reactivate a revoked grant, extend expiry, or attest current usability.
An exact retry is resolved under the subject/grant locks before creation-only expiry,
scoped-identity and active-binding checks. Structural validation, registered context,
subject ownership and healthy operation-clock checks still apply. New grants still
require a current matching scoped identity and binding. Version replacement is future lifecycle.

Permissions: 1..3 unique actions, sorted by action for canonical storage. Closed entries:

- `{action:"prices.read"}`.
- `{action:"order.preview"|"sandbox.execute", max_amount, max_duration, max_price_sun}`.
  Amount 1..1e9, duration 1..2592000, price null or integer 1..1e12. Null means no extra
  price cap, not an infinite amount/duration permission. A non-null cap requires the
  request's `max_price_sun` and bounds it. Existing action-schema bounds also apply.

Trusted config `evidence_policy`: null OR exact
`{profile,policy_version,source_profiles,max_age_ms}`. IDs use draft.2 ID syntax,
source_profiles is nonempty unique list (max16), max_age_ms integer 1..86400000.
No implicit evidence policy. This component accepts registration.environment=sandbox only.

## Evidence

Evidence object, closed; null allowed as above:

```
{ assertion_id, profile, policy_version, source_profile,
  evaluation_mode, result, observed_at_ms, evaluated_at_ms, issued_at_ms, valid_until_ms }
```

IDs follow ID syntax. evaluation_mode = server_recomputed | synthetic. result =
passed | failed | insufficient_data | not_performed. Integer timestamps must satisfy
observed <= evaluated <= issued < valid_until. Issued may not exceed clock.lower.
Updates are stored separately per registered context + subject, under subject lock;
older issued_at updates conflict, same assertion_id cannot change payload, equal-time
different payload conflicts. Passing an earlier failed result never silently restores
an old passed assertion. Clearing evidence stores null under the same serialization.
If policy is required: matching profile/version/allowed source, passed result,
clock.upper < valid_until and clock.upper-observed <= max_age are all required.
Synthetic is explicitly sandbox-only; it never establishes physical consistency.
Evidence shown in signed material is the selected immutable summary, never raw sensors.

## Signed wire format

Both profiles are compact JWS ES256, EXACT header `{alg:"ES256",typ,kid}` and EXACT
claims `{iss,aud,sub,iat,exp,jti,profile,data}`. kid/jti IDs follow ID syntax.
sub is scoped_subject, iss/aud equal trusted registration. No private JWK/header URLs,
crit, embedded key or extra claims. Canonical base64url; 64-byte ES256 signature;
bounded strict UTF-8 JSON rejects duplicate keys/prototype keys/nonfinite/deep values.
Maximum token 32768 bytes, header 2048, payload 24000, depth12.
Use real signatures, not an untrusted decoded payload.
Integers have JSON numeric value semantics: finite integral `1.0`/`1e0` normalize to
1; booleans, fractions, unsafe integers and overflow are rejected. Original draft.2
context/action hash bytes and numeric normalization remain unchanged.

NumericDate iat=floor(issued_ms/1000), exp=ceil(valid_until_ms/1000). Millisecond fields
are authoritative and MUST also be enforced. Ceil prevents same-second rounding from
making a valid short assertion unsignable. No extra one-second validity is granted.

### Grant snapshot

typ=`atum-grant-status+jwt`, profile=`atum-grant-status-v1-draft.1`.
data is EXACT `{grant,status,evidence,issued_at_ms,valid_until_ms}`.
status is `active` only. Grant is the object above. issued_at=clock.now;
valid_until=min(issued_at+30000,grant expiry, evidence expiry IF evidence policy required).
An inactive, expired, unbound or insufficient-evidence grant cannot receive a new snapshot.
For required evidence, the transaction/return guard also ends at
`observed_at_ms + max_age_ms + 1`, the first invalid millisecond. This guard does not
change the signed `valid_until` calculation above. Crossing it before COMMIT returns
`expired`; crossing it after COMMIT returns `temporarily_unavailable`. Consumers
must still check evidence freshness when consuming the snapshot.
Token jti is random ID. This snapshot is not a permit and can become stale after revocation.
Node verifyGrantSnapshot(assertion,context,actionRequest,clientId) returns verified frozen
data + `authorization_effect:"reservation_only", requires_admission:true`.
It verifies context template/client/grant expiry/status and current evidence-policy/time,
but does not replace MERX policy enforcement or atomic quota reservation.

### Admission

typ=`atum-admission+jwt`, profile=`atum-admission-v1-draft.1`.
data is EXACT `{context,intent_hash,admission_id,decision,reason,evaluated_at_ms,
evaluated_uncertainty_ms,grant_expires_at_ms,acceptance_expires_at_ms,
first_submit_expires_at_ms,evidence}`.
decision admitted|denied. reason `admitted` for admitted; denied reasons exclusively
grant_not_active | grant_expired | account_not_bound | action_not_permitted |
parameter_limit | evidence_insufficient. Denied decisions are persisted too.

For admitted: acceptance=min(evaluated+10000,grant expiry),
first_submit=min(evaluated+30000,grant expiry). Evidence is checked at admission;
later evidence expiry/status changes do not renew or mutate this committed permit.
Both deadlines are immutable. ATUM's new admission transaction must keep healthy
clock.upper before acceptance expiry at COMMIT AND successful return. The resource's
separate acceptance transaction follows the MERX sandbox rule below.
At evaluation, acceptance must also be after evaluated+uncertainty; no future evaluation
or evidence issued after evaluated-uncertainty is accepted, even for optional evidence.
For denied: both deadlines null. All decisions carry the original evidence summary.
jti=admission_id. iat=floor(evaluated/1000). exp=ceil(first_submit/1000) for admitted,
ceil((evaluated+300000)/1000) for denied. No timestamp arithmetic overflow.

Store key = draft.2 operation_key (incl namespace, not grant/key/period).
Save exact full context, intent hash and assertion atomically. Existing operation with
different full intent conflicts, even if action_hash is unchanged. Exact retries return
the SAME compact assertion including after revoke, expiry, restart or lost response.
retrieve never creates a decision and never signs a fresh permit.
Revocation and new admission serialize on subject then grant; whichever commits first
defines the outcome. An original admitted decision survives subsequent revocation only
within its original deadlines and existing MERX operation state. No automatic resubmit.

Node verifyAdmission(assertion,context,actionRequest,{mode:"accept"|"inspect"}):
- accept: strict signature/context/shape/caps/current measured time; admitted assertion
  must be before acceptance expiry. Returns `authorization_effect:"admission"` only
  for admitted. Denied asserts none. Caller still atomically accepts into MERX ledger.
- inspect: checks cryptography, original shapes/bindings/caps, permits historical expiry,
  returns `authorization_effect:"none"` and `historical:true` always. This is for
  reconciliation; it cannot newly accept/submit an operation.
- Denied assertions also expire in accept mode at evaluated+300000. Historical inspect
  remains available and always returns no authority.
- There is NO token-only first-submit function. MERX must require its durable accepted
  state plus clock.upper < original first_submit expiry. Unknown outcomes reconcile.

### MERX sandbox acceptance

This compatibility rule applies to the MERX sandbox integration. For generic
service acceptance, see the [resource guide](../../docs/resource.md).
Let `A=min(evaluated_at_ms+10000,grant_expires_at_ms)` and
`S=min(evaluated_at_ms+30000,grant_expires_at_ms)`. Every time guard uses a healthy
measured clock and strict `clock.upper < deadline`. These are sandbox windows;
production clock-health agreement remains open.

1. ATUM's new admission signing/storage COMMIT and successful return remain before A.
2. MERX commits the exact verified admitted assertion and original full context on
   a still-prepared operation, with pre/post-COMMIT guards at A. Staging alone grants
   no execution authority; an ambiguous response is not confirmed acceptance.
3. A separate MERX confirmation transaction locks the current account/binding and
   subject, reads the exact committed decision/context and observes healthy upper<A.
   Those locks remain held through confirmation COMMIT. The witness is generated
   by the trusted resource, never supplied or backdated by a caller.
4. That same transaction atomically commits accepted state and its immutable event
   containing `acceptanceWitnessUpperMs`. COMMIT/return are guarded by S. They may
   finish after A only for that transaction's qualifying observation from step 3.
   A rolled-back witness cannot be reused. A lost successful confirmation response
   recovers the saved accepted state; it does not create new acceptance or deadlines.
5. First submit independently requires committed accepted state, current account/
   binding checks, healthy upper<S and a single atomic submission claim. A prepared
   decision or historical inspection cannot substitute for accepted state. A
   submitting/unknown operation is reconciled, never blindly submitted again.

This rule does not promise accepted-state COMMIT before A. The witness is an internal
trusted transaction observation, not a public cryptographic proof or production
clock attestation. The agreement changes no signed fields, verifier profile, original
deadline or package version. Published archives remain immutable; this current-source
clarification does not rewrite draft.8's packaged contract or establish full G0.

Current MERX active-account/binding checks also gate historical expiry/settlement.
A disabled account can therefore retain pending reservations. No administrative
settlement bypass exists in this component. Preserve original decisions, operations,
events and quota records; authorized reactivation or a separately designed/reviewed
administrative lifecycle is required. Do not reset quotas or automatically reactivate.

## Python seam (no routes/startup side effects)

`AuthorityStore(engine, registration, evidence_policy, clock, signer)`.
Opt-in initialize_authority_schema(engine) requires identity+binding schema.
Methods:
- provision_grant(subject_id, grant) -> original public grant/state (trusted consent seam).
- revoke_grant(subject_id, grant_id) -> state; irreversible in this increment.
- set_evidence(subject_id, evidence_or_null) -> stored summary (trusted evaluator seam).
- snapshot(context, action_request, client_id) -> compact signed snapshot string.
- admit(context, action_request, client_id) -> original compact decision string.
- retrieve(context, action_request, client_id) -> original compact decision or not_found.

Subject/scoped identity and active account binding must agree with stored grant and full
registered context. Unknown grant or template/client mismatch is a request error, not a
new durable denial. Authentic caller association is a host responsibility, never inferred
from a bare passport URL. Payload ownership must be copied before waits; later caller
mutation cannot alter a request being processed.

Transactions: PostgreSQL subject->grant->decision locks; SQLite BEGIN IMMEDIATE for
isolated tests. Bounded local lock/statement/idle transaction timeouts and synchronous
commit; injected bounded host pool/connect timeout. No error details/SQL leakage.
Clock supplied per operation: {now_ms,uncertainty_ms,healthy}, uncertainty 0..1000,
healthy true, no backward step/underflow/overflow. Recheck after locks, signature work,
final SQL and COMMIT; after-COMMIT uncertainty returns unavailable, not claimed rollback.
No cross-DB transaction is implied. Decisions are never expired/deleted to allow retries.

Errors: invalid_request, invalid_proof, conflict, not_found, grant_not_active,
grant_expired, account_not_bound, evidence_insufficient, expired, temporarily_unavailable.
All safe codes; no input/SQL/keys in text. Internal unexpected errors unavailable.

## MERX mapping

Snapshot verified grant gives VerifiedAgent.scope, agentKey=template.agent_key_thumbprint,
grantId/version, permissions and grantLimit. validUntil=min(snapshot validity,grant expiry)
converted EXACT integer milliseconds with new Date(ms).toISOString(). Evidence mapping
is one-to-one snake_case ms -> camelCase RFC3339; null means absent, not passed.
Every request also requires draft.3/4 verified proof for the SAME context/client/key.
Store snapshot separately from proof result; don't cast proof-only results to VerifiedAgent.

Admission permit: permitId=admission_id, admittedAt=evaluated_at, acceptUntil=acceptance,
firstSubmitUntil=first_submit. Current MERX `intentHash` retains ACTION HASH for backwards
compatibility; new durable `atumIntentHash` stores full intent_hash, and full signed context
must match on prepare/retry/accept/recovery. Do not overwrite action hash with full hash.
Grant ID/version, agent key, policy and all operation/scope identity fields map directly.
Resource contract must keep the original two deadlines; token refresh never updates them.

No quota amounts are minted by this component. Pricing/payment/chain executors remain
disabled. Full G0 also needs actual owner enrollment/consent, resource transport auth,
OAuth token issuing, independent read proofs, raw HTTP boundary and clock/replay wiring,
CJS/types/package integration and bilateral acceptance.
