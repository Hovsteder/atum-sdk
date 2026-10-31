# Release status and scope

This developer preview contains the public Agent, Verification and PostgreSQL
replay packages, a generic service-action profile, and an independent calendar
resource example. Services choose their own action names. MERX remains an
explicit compatibility integration, not a dependency of the generic path.

## Hosted availability

The self-service entry and public service-access API are implemented in the
private ATUM host. A developer signs in with a passkey, connects an existing
service, chooses its actions and OAuth flows, and receives a scoped backend
credential. An owner separately approves an agent's permission.

**There is no publicly hosted registration/API URL in this release.** Deployment
still needs the selected domain's DNS/access, persistent operator configuration
and ordinary public TLS. Source and local acceptance do not establish that a
public endpoint is running. The SDK cannot manufacture grants or consent when
those services are unavailable.

Service credentials can be rotated and a service can be disabled. New grant
issuance, refresh and current authorization honor the current service lifecycle.
The initial self-service policy has no separate partner-account binding;
integrations with an account-binding policy retain their existing requirement.
Entering a service origin does not verify ownership of its domain or company.

## Evidence and limits

The independent local journey uses actual passkey consent, the OAuth issuer,
signed authority checks, durable PostgreSQL replay/usage, and a calendar resource.
It does not substitute a MERX action or seed a grant. Generated accounts and PKI,
a virtual WebAuthn authenticator, private databases and a declared test clock are
test setup, not production attestation. The final journey connected two services without restarting ATUM, used the public
calendar launcher and Agent, denied a new operation after owner revocation, and
denied token refresh after disabling the second service. All three disposable
databases were stopped and removed. Exact checks are listed in the release notes.

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
