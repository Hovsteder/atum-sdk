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

The hosted journey was exercised with public Passport registration/login,
self-service registration, Device passkey consent, a public Agent/Verify request
through an ephemeral local calendar resource, and grant revocation. The test
owner used a virtual WebAuthn authenticator; it is not phone evidence. The local
calendar resource and its PostgreSQL/replay state were removed. This was not a
MERX action and it did not assert a post-revocation resource invocation.

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
