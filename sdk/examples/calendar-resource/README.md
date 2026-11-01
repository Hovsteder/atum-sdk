# Independent calendar resource

This runnable example is a neutral ATUM service. It registers
`calendar.event.read`; it has no MERX action, account connector, payment model or
delivery result. Owners approve Agent grants through the normal passkey consent
flow. The service then verifies a fresh proof and current signed authority before
its own durable acceptance step.

ATUM hosts Passport, the issuer and service-access API. A service origin entered
during signup is trusted configuration, not proof that the developer owns that
domain; the calendar resource remains the integrator's own backend.

## Connect the service

An enrolled owner opens
[Passport developer](https://passport.atum.digital/developer), enters a service
name, exact HTTPS origin, permission names and either Device flow or HTTPS
authorization-code callbacks. The current self-service policy accepts only
generic actions with no partner-account requirement. The owner can list up to
eight owned registrations, replace a credential and disable a service without a
host restart. A credential is displayed only after creation or replacement.

Save the returned `atum_svc_…` credential in a secret store. It authenticates
the service configuration and authority calls; it cannot approve an owner grant.
Disabling the service denies new consent, issue, refresh and current authority.
Existing immutable revocation/outbox history remains available to the issuer.

The authenticated `GET /v1/service/registration` response contains the exact
registration and descriptor, the authority public keys and evidence policy, and
the issuer JWKS URL. It never contains a private signing key. The example fetches
that response and the issuer JWKS over verified HTTPS with no redirects or
unbounded response bodies. It accepts only the exact ATUM RSA verification fields
plus oidc-provider's single known `key_ops` metadata field, which it removes
before constructing the strict verifier. Normal public deployments use the Node
system trust store; the CA-file variables below are for private development PKI.

## Resource setup

Install this workspace's local packages, then configure:

```sh
# From the public repository root:
npm ci --ignore-scripts --no-audit --no-fund
cd sdk/examples/calendar-resource

export ATUM_SERVICE_ACCESS_URL='https://verify.atum.digital'
export ATUM_SERVICE_CREDENTIAL='atum_svc_…'
export ATUM_CALENDAR_DATABASE_URL='postgresql://…'
export ATUM_CALENDAR_ENDPOINT='https://calendar.example/v1/atum/operations'
export ATUM_CALENDAR_TLS_KEY_FILE='/run/secrets/calendar.key'
export ATUM_CALENDAR_TLS_CERT_FILE='/run/secrets/calendar-chain.pem'
export ATUM_CLOCK_OBSERVATION_FILE='/run/atum/clock-observation.json'

# Development PKI only; omit each variable to use normal system trust.
export ATUM_SERVICE_ACCESS_CA_FILE='/run/dev/atum-ca.pem'
export ATUM_ISSUER_CA_FILE='/run/dev/atum-ca.pem'

npm run migrate
npm run export-agent-config -- /run/atum/calendar-agent.json
npm start
```

`npm run migrate` is an explicit operator step. It runs the published
`@atum/replay-postgres/migrate` port for migrations 001 and 002, creates this
example's usage and calendar tables, and exits. Runtime startup does not silently
repair schema. The migration is safe to repeat, upgrades an exact migration-001
schema, and rejects an altered or foreign installed replay catalog.
`export-agent-config` writes a new owner-only file containing only the public
service registry and resource endpoint. It refuses to overwrite an existing
file. The backend service credential stays with the resource operator and is
never given to an Agent.

The clock observation file must be replaced atomically by a trusted local clock
observer. It is exact JSON:

```json
{"healthy":true,"now_ms":1800000000000,"observed_monotonic_ns":"123456789000","uncertainty_ms":5}
```

`observed_monotonic_ns` uses the host monotonic clock. The example advances the
sample only by measured monotonic elapsed time, rejects rollback or stale samples,
and fails closed if uncertainty exceeds 1000 ms. There is no `Date.now()` healthy
fallback. `ATUM_CLOCK_MAX_AGE_MS` defaults to 1000 and may be set from 1 through
60000 for a measured deployment policy.

## Run a Device Agent

The same service registration is enough to run the included public Agent entry
point. It creates an in-memory P-256 Agent key, prepares the registered Device
request, prints the owner verification URI and user code, polls once, performs
the resource nonce challenge, and submits one calendar read. It never prints the
token or private key.

```sh
export ATUM_AGENT_CONFIG_FILE='/run/atum/calendar-agent.json'
export ATUM_CALENDAR_CA_FILE='/run/dev/calendar-ca.pem' # omit for system trust
export ATUM_CALENDAR_ID='main'
export ATUM_CALENDAR_LIMIT='10'
npm run authorize
```

The Agent does not retry an ambiguous business request. A new process creates a
new Agent key and authorization; production agents must own secure key and token
persistence.

## Authorization and acceptance boundary

`resource.mjs` uses public `@atum/verification/current-authorization` APIs. For
each protected request it verifies the access token and DPoP proof, consumes
replay state, fetches a fresh signed grant snapshot, requests a fresh signed
admission and checks both assertions. The returned fact is
`current_permission`; it is not a business-success or delivery attestation.

`usage-store.mjs` is the service-owned acceptance layer. In one PostgreSQL
transaction it locks the actual grant identity across operation namespaces,
checks the exact saved context, counts prior accepted operations and enforces the
original `grant_limit`. It retains the minimum of presented and originally saved
token, grant, snapshot, acceptance and first-submit caps. Those caps are checked
before waits and work, before commit and after commit. An exact local retry may
recover a saved result only while the original caps remain current. After expiry
the row is historical data and cannot authorize a response or execution.

The sample query binds `calendar_events.scoped_subject` to the verified owner;
caller-selected `calendar_id` cannot cross subjects. The sample's effect is a
local PostgreSQL read. It makes no exactly-once claim for an external side effect,
which needs its own durable outbox and acceptance policy.

The HTTPS handler rejects duplicate `Host`, `Authorization`, `DPoP`, content or
framing headers before verification. A nonce-omitted proof can only issue a
durable nonce; it cannot consume business usage. The unchanged continuation may
reach current authority and resource acceptance.

There is no public status/read endpoint, automatic re-admission or unlimited
recovery right. Historical authority inspection is separate from a fresh
permission check.

## Focused checks

```sh
ATUM_EXAMPLE_DATABASE_URL='postgresql://…' node test/usage-store-postgres.test.mjs
```

The joined private harness creates real owner passkey consent, issuer tokens,
current authority and resource PostgreSQL state for two independently registered
services. The second service proves token issuance and disable/refresh denial; it
does not invoke a second business resource.
# Calendar resource reference

See [the public quickstart](../../../docs/quickstart.md) and [Node hosting boundary](../../../docs/node-hosting.md). The resource verifies fresh `current_permission` and then makes its own durable acceptance; it never treats verification as a business result. The Agent state directory holds an owner-only P-256 private key and tokens. Back it up only as sensitive credential material; loss requires fresh consent, and an ambiguous refresh or invocation must not be retried automatically.
