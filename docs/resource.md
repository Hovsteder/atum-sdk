# Check passport and permission at your service

ATUM checks an agent's connection to its owner's passport, the owner's current
permission and the signed request. Your service performs its own operation.
Permission names belong to your service: a calendar might register
`calendar.event.read`; a document service might register `document.read`.
Neither service needs MERX, Energy, order or payment fields.

## Connect an existing service

Register your service's origin and action names in the [ATUM developer entry](service-registration.md).
Use the resulting trusted registration and service access credential on your
backend. The credential authenticates your service to ATUM. It cannot create an
owner's permission or replace the owner's consent.

A request contains a registered action name and canonical JSON parameters.
The first generic permission format authorizes the named action. Your service
still checks the business parameters and data ownership. For example, permission
to read a calendar does not grant access to another owner's calendar.
Unsupported permission restrictions are rejected; they are not silently ignored.

Partner-account linking is a service policy. It is not mandatory for every
integration. The first generic self-service path uses owner consent without a
separate partner-account connection. Existing integrations that require a real
account binding keep that requirement.

## Verify a request

Use `createCurrentAuthorizationVerifier` from
`@atum/verification/current-authorization`. The composition:

1. Verifies the issued token, agent signature and complete request context.
2. Consumes the bound nonce and replay identity through durable storage.
3. Fetches and verifies a fresh signed grant snapshot and admission from ATUM.
4. Returns the scoped owner subject, agent/client identity, authorized action,
   original grant limit and original expiry deadlines.

The result has `authorization_effect: 'current_permission'` and
`requires_resource_acceptance: true`. It is permission for your service to
consider the original request. It is not a receipt for completed business work,
a remaining-balance counter or proof that an external action succeeded.

The low-level `createVerifier` API only verifies a request proof. Its
`authorization_effect: 'none'` result is intentionally insufficient for execution.
Historical signed decisions are also separate from a fresh permission check.

## Keep your service's rules

After verification, your service checks its own data access and business rules,
accounts for usage, and records the operation and outcome durably. Preserve the
original identity and deadlines through queue/lock waits. Do not count different
operation namespaces as new grants or invent a new operation ID after a timeout.

The [calendar example](../sdk/examples/calendar-resource/README.md) checks calendar
ownership using the verified scoped subject and records grant usage and local
query results in PostgreSQL. Its local transaction is not a claim of exactly-once
execution at an external payment/provider service.

A timeout can leave the outcome uncertain. The verification composition does not
automatically admit again or retry business work. Recovery uses your service's
saved original operation and authorized recovery process. Public agent status/read
permissions are not implied by invocation permission.

## Host requirements

Preserve the raw request body and security headers until verification. Check the
configured HTTPS endpoint and reject ambiguous duplicate headers, JSON and
framing. The nonce challenge checks the initial signed request before issuing a
nonce; it does not execute work or reserve business usage.

Use durable [nonce/replay storage](../sdk/packages/replay-postgres/README.md),
bounded connections/concurrency and a healthy observed clock. Apply migrations
explicitly. Do not seed grants, reset usage or disable TLS validation on startup.
Keys for issuing agent tokens, signing authority decisions and authenticating a
service have different roles. A service credential never becomes owner consent.

For Node HTTPS services, `@atum/verification/node-http` supplies
`createProtectedHttpHandler`. Mount it before parsers on the direct TLS server;
it validates raw framing, headers, body and nonce/current permission before it
calls the resource's acceptance callback. It does not trust forwarded headers.
Supported proxying is transparent TCP/SNI pass-through, rather than ordinary
HTTP TLS termination. The local `atum-clock` observer uses local chronyd and
writes atomic observations; stale, unhealthy, or wall-step evidence fails closed.

## MERX compatibility

MERX is the first reference integrator. It owns its action validators, pricing,
accounting, provider calls, business results and recovery. Existing MERX profiles
retain their exact hashes, permission constraints and wire formats through an
explicit compatibility path. Generic name-only permissions do not replace an
existing exact-quote purchase permission.

See the [verification API](../sdk/packages/verification/README.md) for the concrete
configuration and errors, and [release status](status.md) for what is published,
tested locally and publicly hosted.
