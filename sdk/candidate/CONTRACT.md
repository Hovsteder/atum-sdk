# Admission context candidate — 0.1.0-draft.2

Status: unfrozen interoperability increment. This is a pure validation/reference package,
not an issuer, signed permit, owner proof, clock monitor or authorization service. The
published draft.1 seed stays unchanged. G0 still needs authenticated transport, complete
consent/ingestion contracts and signed positive/negative vectors. Nothing here enables
MERX protected or financial routes.

## Resource action and canonical bytes

The exact MERX MC-001 resource-profile.json is pinned by SHA-256
`dc6f6409a47da2a97ea7b4ace313985d7fcd4c6b8459a59ea06b014de304a175`.
`prices.read` parameters are `{}`. `order.preview` and `sandbox.execute` require resource
ENERGY or BANDWIDTH, amount integer 1..1000000000, duration integer 1..2592000 seconds;
optional max_price_sun integer 1..1000000000000 is advisory SUN per unit, never a spending cap.
Unknown fields, bool/null/string numbers, fractions, nonfinite values are rejected.
Integral JSON numbers 1, 1.0 and 1e0 represent the same value and serialize as 1.

Action canonical JSON uses keys action,parameters in that order; parameters use
amount,duration,max_price_sun(if present),resource. UTF-8, no whitespace. action_hash is
`sha256:` + lowercase SHA-256 of UTF-8 `merx.atum.intent.v1\n` followed by those bytes.
The published prices.read vector remains unchanged. This closed schema is not a general
JSON canonicalization implementation. Duplicate JSON keys must be rejected before parsing
at a wire boundary; object-level helpers cannot discover keys a parser already discarded.

## Complete context

All fields below are required, no extras. Context contains only strings, integers and null;
there are no nested objects. Canonical context bytes: validate, sort keys by ASCII code,
serialize compact UTF-8 JSON. Strings are restricted to the ASCII sets below, thus there
are no escape, Unicode normalization, locale or floating-point choices.
In every record an integer means a finite integral JSON number: 1, 1.0 and 1e0 are
equivalent and canonicalize as 1. Booleans never count as integers. Helpers do not mutate
their input. All arithmetic additions must stay within the safe integer range; overflow
is invalid input, not an eligible operation.
`intent_hash = sha256:` + lowercase SHA-256 of UTF-8 `atum.admission.context.v1\n`
followed by the canonical context bytes. Hashes provide binding, not authentication.

| Fields | Value constraints |
| --- | --- |
| protocol_version | exactly 0.1.0-draft.2 |
| resource_profile_version | exactly v1-draft.1 |
| resource_profile_hash | sha256: plus pinned MC-001 digest above |
| issuer, audience | 1..256 ASCII characters `[A-Za-z0-9:/._-]`; exact registered identifiers, never normalized or used as fetch URLs |
| environment | sandbox (this candidate enables no production policy) |
| tenant_id, resource_id, quota_scope_id, operation_namespace, scoped_subject, operation_id, grant_id, policy_version | 1..128 ASCII characters `[A-Za-z0-9._:-]` |
| grant_version | integer 1..9007199254740991 |
| agent_key_thumbprint | 43 base64url characters, unpadded SHA-256 JWK thumbprint; byte canonicality checked |
| consent_hash, action_hash | sha256: plus 64 lowercase hex |
| account_binding_id | null or 1..128 ASCII characters `[A-Za-z0-9._:-]` |
| account_binding_version | null if account_binding_id is null; otherwise integer 1..9007199254740991 |
| action | prices.read, order.preview or sandbox.execute |

Full input is `{context, action_request}`. Validate both, require action equality and recompute
action_hash. Trusted registration is a separate required argument with EXACT fields:
issuer,audience,environment,tenant_id,resource_id,quota_scope_id,operation_namespace,
resource_profile_version,resource_profile_hash,policy_version,account_required_actions.
The last field is an array of distinct known actions (may be empty). Every other field must
match context. Registration is local configuration, not something the agent can choose.
Account ID/version nullability is paired; required actions reject null bindings. This only
validates a reference: current binding state, subject/account ownership and both owner proofs
MUST be verified by the authority/resource before authorization.

The deduplication tuple is issuer,environment,tenant_id,resource_id,quota_scope_id,
operation_namespace,scoped_subject,operation_id (in that order). Common quota tuple is
issuer,environment,tenant_id,resource_id,quota_scope_id,scoped_subject. A new namespace
never creates a new common allowance. Period, client, grant and key never enter operation
deduplication. Grant/key/consent/account/policy changes alter intent_hash and conflict on the
same operation; no silent replacement of the stored binding.

Nonce, challenge, JWT iat/jti, retry time and evidence refresh are outside business context.
Their proof and status checks are separate. The authority stores original decision/evidence
bindings. Retrying an operation returns its original decision even if a transport nonce or
evidence status changed, and never extends the original deadlines.

## Admission decision and clock boundary

Synthetic decision object has EXACT fields: protocol_version (draft.2), synthetic (true),
authorization_effect (none), context, intent_hash, admission_id (same 1..128 ID alphabet),
decision (would_accept or would_reject), reason, evaluated_at_ms, evaluated_uncertainty_ms,
grant_expires_at_ms, acceptance_expires_at_ms, first_submit_expires_at_ms.
All *_ms timestamps are nonnegative integers <=9007199254740991. This draft.2 reference
uses integer UTC milliseconds explicitly; it does not silently reinterpret draft.1 RFC3339
fields. Production wire naming/transport is still subject to the complete G0 contract.
evaluated_uncertainty_ms is 0..1000, describing the issuer's healthy measured bound.

For would_accept reason is synthetic_example_only; deadlines MUST equal
min(evaluated_at_ms+10000, grant_expires_at_ms) and
min(evaluated_at_ms+30000, grant_expires_at_ms), respectively. Both must be strictly after
evaluated_at_ms. Reject overflowing additions. For would_reject both deadlines are null;
reason is grant_not_active, evidence_insufficient, action_not_permitted or account_not_bound.
No real permission is conveyed by either result.

Clock input for a local eligibility calculation is EXACT `{now_ms, uncertainty_ms, healthy}`.
now_ms is the local UTC estimate, uncertainty_ms integer 0..1000, healthy is bool. A trusted
clock adapter must supply it, invalidate stale measurements, wall-clock jumps or lost sync,
and include sampling/drift error in the bound. Client values and a DB clock alone do not
establish clock health. This package does not implement that adapter.

Unhealthy clocks block new acceptance/first submit; read/reconcile remain possible.
Reject an issuer evaluated_at_ms later than local now_ms + local uncertainty_ms + issuer
evaluated_uncertainty_ms. Acceptance is eligible only if local now_ms + uncertainty_ms is
STRICTLY before acceptance_expires_at_ms. First submit uses the separate first-submit
deadline and additionally requires an existing, durably accepted operation. The pure helper
requires an explicit `already_accepted` bool; a client claim is not a durable state proof.
No positive JWT leeway extends either deadline. An expired permit never authorizes a new
effect. A previous/unknown submit must reconcile, not retry or release reservation.

## Owner/account confirmation transcript

Exact statement fields: protocol_version, purpose=bind_account, issuer,audience,environment,
tenant_id,resource_id,quota_scope_id,scoped_subject,account_binding_id,account_binding_version,
account_ref,request_id,nonce,created_at_ms,expires_at_ms. Identifiers follow context constraints;
account_ref/request_id use the ID alphabet, nonce is canonical unpadded base64url encoding of
32 random bytes; expiry is strictly later than creation. Account ID/version must be nonnull.
No wallet address or public passport URL substitutes for ownership.

This is the common typed transcript to be covered by BOTH a MERX authenticated owner
confirmation and an ATUM purpose-bound owner confirmation. Both must cover identical bytes,
nonce, subject, account reference and version. `account_statement_hash` uses the same sorted
closed canonical form with domain `atum.account.binding.v1\n`. A hash or a reference to a
proof is not either proof. Actual authenticated signing, verification, one-time challenge
consumption, expiry enforcement and persistent state transition remain G0/G1 work. No endpoint
accepts this statement alone. Account changes/revocation require a new version and review of
affected grants; recovery does not recreate allowance or reactivate grants.

## Reference interface and vectors

Python `reference.py`: canonical_action(request)->str; action_hash(request)->str;
validate_bound_intent(context, action_request, registration)->None;
canonical_context(context)->str; intent_hash(context)->str;
operation_key(context)->tuple; quota_key(context)->tuple;
validate_decision(decision)->dict (normalized copy); eligible(decision, clock, stage, already_accepted=False)->bool;
canonical_account_statement(statement)->str; account_statement_hash(statement)->str.
stage is acceptance or first_submit. Invalid input raises ValueError; valid but unhealthy,
expired, not accepted or rejected decisions return False. No IO, auth, signing or persistence.
Node conformance checker independently recomputes hashes from the documented shapes and
tests mutations against Python, using built-in crypto only. Shared vectors contain synthetic
identifiers and expected literal hashes; recomputing an expected value with the same function
under test is not a golden vector.
