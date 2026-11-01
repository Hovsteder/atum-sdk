# Release status and scope

This developer preview contains the public Agent, Verification and PostgreSQL
replay packages, a generic service-action profile, and an independent calendar
resource example. Services choose their own action names. MERX remains an
explicit compatibility integration, not a dependency of the generic path.

## Hosted availability

The hosted self-service entry is
[atum.digital/developers](https://atum.digital/developers). Create or sign in to
[Passport](https://passport.atum.digital/), then register and manage an existing
service at [Passport developer](https://passport.atum.digital/developer). The
issuer is `https://auth.atum.digital`; a backend uses
`https://verify.atum.digital` as its service-access API. A developer chooses
actions and OAuth flows and receives a scoped backend credential. An owner still
separately approves each agent permission.

Service credentials can be rotated and a service can be disabled. New grant
issuance, refresh and current authorization honor the current service lifecycle.
The initial self-service policy has no separate partner-account binding;
integrations with an account-binding policy retain their existing requirement.
Entering a service origin does not verify ownership of its domain or company.

## Evidence and limits

Public kit **0.1.0-rc.3** adds measured chrony observations, a composable raw
Node HTTPS handler, and a durable reference Device Agent with explicit refresh.
The full walkthrough is in [quickstart](quickstart.md).

On 1 November 2026, a clean archive of public source
`aeeaf2fd76bf332377a6243385e0c6ffaf1c0220` installed with `npm ci` and passed
`scripts/hosted-acceptance.py --run` against the public Passport, issuer and Verify
hosts. It created an owner and service, obtained actual passkey consent and Device
tokens, and completed two calendar requests. A fresh Agent process returned a
saved result with no new HTTP; its key survived explicit token rotation. The
resource and its private PostgreSQL cluster restarted without losing acceptance.
A fresh request after owner revocation was denied as `grant_not_active`, with no
additional resource acceptance. Local processes, database and keys were cleaned.

The browser used a virtual CTAP2 passkey; this is not phone-history evidence.
Local fixture data consisted of an empty calendar, a temporary CA, Unix-socket
PostgreSQL and transparent TCP forwarding to the real TLS resource. Public and
resource TLS validation remained enabled. Time came from actual local chrony.
The test imported no private ATUM source and seeded no consent, token or grant.
The public test passport/service audit remains. Later release changes are docs
and packaging metadata, not a rerun of that journey.

Changed-boundary tests cover HTTP framing, current signed authority before the
application callback, typed errors, timeout/concurrency/drain, clock health, and
Agent process recovery/locking/refresh ambiguity. Type checks and public package
imports also pass. In the workspace run one existing Device-flow network-wait
assertion timed out under parallel load; its unchanged isolated file passed all
12 cases. The other package groups passed (verification 215, replay 29, reference
Agent 2); the initial Agent group passed 83/84 before the isolated repeat.

Earlier MERX evidence remains at its original tested revisions: actual owner
connection and code/Device tokens, shared quota, revoke denial, response loss,
server recovery and service/database restart. It is not presented as a new run
of every MERX scenario for this SDK release.

Generic permissions authorize registered action names. Business parameter
validation, data ownership, usage and external-operation recovery belong to the
integrator. A `current_permission` result is not a completed operation or a
remaining-balance counter. Unsupported permission restriction fields reject.

## Distribution

The public repository and matching GitHub release tarballs are the distribution
channel. Package names do not imply npm registry publication. The private ATUM
server, OAuth hosting and sensor-consistency engine are not exported here.

## Separate product work

The native Passport collection SDK and physical sensor-history evaluation,
Galactica certificates, general agent status/read authorization and real MERX
Energy execution have separate delivery and deployment requirements. Web
passkey consent establishes owner approval under its policy; it does not
establish physical history or unique human identity.

The Apache-2.0 license applies to the published SDK code. Hosted service access
and operational terms are separate.

## Hosted presentation follow-up — 1 November 2026

Passport, its developer portal and the issuer now share the main Atum site's
navigation, icons and terminology. Signed-out service registration is disabled
with a sign-in invitation. The portal explains the one-time service secret and
shows redirect URLs only for authorization-code flow. Consent explicitly notes
that service domain/company ownership has not been verified. The issuer root
redirects to the developer entry. No protocol or package release changed.

The public hosted acceptance driver at `8d6e48e1de2090e15b7b75f53308f5c24c0bdbf6`
passed once after this rollout with the same explicit fixtures described above:
actual owner/service registration and passkey consent, two calendar requests,
Agent process recovery, token refresh, private PostgreSQL restart and denial of
a fresh request after owner revocation. Local cleanup completed without errors.
The UI selector update follows the new Sign in / Confirm your code labels; it
does not change authorization or replace the real hosted services with mocks.
