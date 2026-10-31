# ATUM protected request proof profile — v1-draft.1

Unfrozen G0 component, sandbox only. Consumes the immutable draft.2 context contract.
Successful verification establishes a signed request and token/key binding, NOT grant
status, account ownership, physical consistency, admission or permission to execute.
Every new protected operation still requires authoritative online admission.

Standards: [DPoP RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html),
[JWT access token RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html).
Cryptography is delegated to pinned jose 6.2.14. Strict JSON scanning uses Microsoft's
jsonc-parser 3.3.1 with comments/trailing commas disabled. No custom cryptography or OAuth
authorization server. This package is private during development; no publish/deploy.

## Interfaces

`context.mjs` exports `parseStrictJson(input, maxBytes=32768)`, `canonicalAction(request)`,
`actionHash(request)`, `canonicalContext(context)`, `intentHash(context)`,
`validateBoundIntent(context, request, registration)`, `operationKey(context)`, `quotaKey(context)`.
Input is plain JSON data. Context/registration and action rules are exactly
`../../candidate/CONTRACT.md`; no unit/version/bytes changes. Errors are TypeError.
parseStrictJson accepts UTF-8 string or Uint8Array, rejects invalid UTF-8, duplicate decoded
object keys (including escaped duplicates), comments, trailing commas, nonfinite numeric
results, depth >12, top-level non-object, prototype keys (__proto__/constructor/prototype)
and size above maxBytes. It uses the standard scanner then JSON.parse, not a homemade parser.

`verifier.mjs` exports async `createVerifier(config)` returning
`{ verifyProtectedRequest(input) }`, plus `VerificationError` with safe `.code`.
Config EXACT fields: registration (draft.2), issuerKeys (public RSA JWK array), endpoint
(`{method:'POST',url}`), clock (function), replayStore (object with async consume).
Registration is trusted and snapshotted. Endpoint is a canonical HTTPS URL without query,
fragment, credentials or percent escapes; exact registered origin/path, never derived
from client headers. No automatic URL fetch or discovery. Config fields cannot be supplied
by agent requests. No default clock or in-memory replay fallback.

### Additive nonce challenge preparation

The nonce-challenge subpath exports createNonceChallengeVerifier with exact
registration, issuerKeys, endpoint and clock configuration, and shares the same
VerificationError constructor as the complete verifier. Its method,
verifyNonceChallengeRequest(input,{deadlineAt}), receives the normalized
complete-verifier input. Options contain exactly one finite absolute monotonic
deadline with positive remaining budget at most 5000ms. Invalid factory or
options input is TypeError. Expiry after a request has started is safe
temporarily_unavailable.

The challenge proof has exactly jti, htm, htu, iat, ath and atum_intent_hash. It
passes the same registered endpoint, strict body/context, RS256 access-token,
ES256 P-256 JWK/JKT, signature, ath, intent-hash and 60-second measured-clock
freshness checks as a complete proof. A nonce member, malformed full proof or
any extra member is invalid proof and cannot select this path. The verifier
checks its deadline after every cryptographic await and re-samples measured time
before returning.

The only success value is a frozen closed fact carrying nonce_issue_only,
issuer/audience, endpoint URL, agent-key thumbprint, proof JTI, intent hash,
token/proof/replay times, and verified clock bounds. It is a trusted store input
only: no replay acceptance, authority, admission, quota reservation or
permission to execute follows from it. This package increment mounts no HTTP
response, persistence, or host route.

Input EXACT fields: authorization (single string Authorization header), dpop (single string
DPoP header), body (string or Uint8Array), method, url. Adapter must reject duplicate HTTP
headers before calling; arrays, joined comma values, controls/newlines are rejected here.
Method/URL must exactly match registered endpoint; this invocation profile has no query.
Authorization scheme DPoP is case-insensitive, accepts one or more ASCII spaces followed by
one compact JWT; Bearer is rejected. DPoP value is a single compact JWT. Token <=16384 bytes,
proof <=8192 bytes, body <=32768 bytes; complete Authorization header <=16416 characters.
Cheap character/byte bounds run before copying, decoding, encoding or scanning inputs.
Every JWS segment is canonical unpadded base64url;
decoded header/payload must be strict JSON (header <=4096 bytes, payload within token limit).

Body is EXACT `{context,action_request}`. Validate all draft.2 fields, registration and
resource action bindings before deriving intent_hash. Do not trust caller-supplied hash alone.

## Token

Header EXACT `{typ:'at+jwt',alg:'RS256',kid}`. Key only from trusted issuerKeys by exact kid;
no jku/x5u/header jwk/crit/algorithm negotiation. Each trusted JWK is EXACT
`{kty:'RSA',n,e:'AQAB',kid,alg:'RS256',use:'sig'}`; n is canonical base64url, modulus 2048..4096
bits. No private parameters, duplicate kids, remote resolver or token-driven key refresh.
Key rotation is explicit configuration replacement; old keys can coexist by distinct kid.

Payload required fields: iss,aud,sub,client_id,jti,iat,exp,cnf,scope,atum.
Optional nbf only; no other fields. iss and SINGLE string aud exactly match registration.
sub equals context.scoped_subject. client_id and jti use the context ID alphabet/length.
scope exactly `atum:invoke`. cnf EXACT `{jkt}`, matching agent key thumbprint in context.
iat/exp/optional nbf are nonnegative safe integer NumericDate seconds, bounded so ms conversion
is safe. exp>iat, exp-iat<=300s. exp*1000 must be STRICTLY above local now+uncertainty.
iat*1000 cannot exceed local now+uncertainty; optional nbf*1000 <= local now-uncertainty.
Use jose.jwtVerify with fixed algorithm/issuer/audience/type/currentDate, zero positive expiry
leeway, plus these profile constraints. There is no online status cache in this package.

atum EXACT fields: proof_profile=`atum-dpop-v1-draft.1`, environment, tenant_id, resource_id,
quota_scope_id, operation_namespace, resource_profile_version, resource_profile_hash,
policy_version, grant_id, grant_version, consent_hash, account_binding_id, account_binding_version.
Each field except proof_profile must exactly equal context. Token is per grant/account
binding, not per operation; operation_id/action/parameters are bound by DPoP below. Scope
does not grant arbitrary actions: named action restrictions remain authoritative admission.

## DPoP and request integrity

Header EXACT `{typ:'dpop+jwt',alg:'ES256',jwk}`; JWK EXACT `{kty:'EC',crv:'P-256',x,y}` with
canonical 32-byte coordinates, no private d or key URL. Use jose.importJWK/jwtVerify and
calculateJwkThumbprint. Computed thumbprint must equal token cnf.jkt and context agent key.

Payload EXACT `{jti,htm,htu,iat,ath,nonce,atum_intent_hash}`. jti is 16..128 base64url characters;
agents generate >=128 bits fresh entropy per proof. nonce is canonical unpadded base64url of
32 random bytes, issued by the server. htm/htu exactly equal the registered endpoint.
iat is safe nonnegative integer seconds, no farther in future than local now+uncertainty,
and local now+uncertainty - iat*1000 <=60000ms. ath is the base64url SHA-256 of the EXACT ASCII
access token string and must match. atum_intent_hash must equal recomputed full context hash.
`atum_intent_hash` is an explicit ATUM extension permitted by RFC9449 §4.2, not an IETF claim
or claim that standard DPoP by itself signs the body. Unknown fields/rights fail closed.

## Clock/replay boundary and result

clock() returns EXACT `{now_ms,uncertainty_ms,healthy}` from a trusted local adapter.
Integers are safe; uncertainty 0..1000ms. Unhealthy/unmeasured/overflow -> temporarily_unavailable.
Measured uncertainty bound remains a candidate setting, not an agreed production clock SLA.
The adapter must invalidate stale samples, lost sync and clock jumps. No default Date.now.
Time is refreshed after signature checks and again after replay consumption; expiry and
proof freshness are rechecked, and a backward jump fails unavailable. If the last check
fails, the nonce may already be consumed: the caller needs a fresh proof/nonce while keeping
the same operation identity. Values outside the
JavaScript Date range are unavailable. Trusted adapter functions and request inputs are
snapshotted so caller mutation during asynchronous verification cannot change the request.

After ALL structure, binding, signature and time checks, call replayStore.consume ONCE with
EXACT `{issuer,audience,agent_key_thumbprint,proof_jti,nonce,endpoint_url,intent_hash,
now_upper_bound_ms,replay_expires_at_ms}`. replay_expires_at_ms = proof_iat*1000+61000,
safe arithmetic required. Store must atomically validate server-issued nonce bound to the
same issuer/audience/key/endpoint with expiry strictly after now_upper_bound_ms, consume it,
and insert replay uniqueness `(issuer,audience,key,proof_jti)` independent of nonce/operation.
Unknown/expired/used nonce or seen jti -> false without partial consume. Backend outage or
exception -> temporarily_unavailable; only literal true means success. Multiworker/restart
implementation must be persistent. This package supplies the REQUIRED adapter port only;
unit tests use an isolated memory implementation which is not exported or production-ready.

Result is a new immutable plain object with proof_verified=true, authorization_effect='none',
requires_admission=true, context (validated snapshot), intent_hash, client_id,
token_expires_at_ms, proof_jti. Never include access token, proof JWT or nonce in result/logs.
No method returns execute/allow, does a network call, reserves quota or issues admission.
Error codes: invalid_request (HTTP/body/context), invalid_proof (token/proof/nonce),
temporarily_unavailable (clock/replay availability). Do not expose crypto
library exception details or input tokens. Invalid config rejects factory creation.

## Tests and next dependencies

Tests sign fresh synthetic RSA and P-256 keys with jose. Positive token+DPoP must verify;
negative signed vectors cover wrong issuer/audience/env/grant/key/account/intent, alg/type,
signature, ath, nonce, htu/htm, expired/future proof, unknown/duplicate fields and replay.
Concurrent identical proof -> at most one success using an atomic test store; outage fails
closed. Test output is proof validation evidence, not real owner consent or physical history.

Next G0: integrate the separate persistent replay/nonce adapter, issuer with oidc-provider, exact owner
consent proof and status/admission signed contracts, ingestion profile and complete shared
bundle. Existing draft.1/draft.2 releases are immutable and are not edited by this increment.
