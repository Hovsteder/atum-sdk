# Release status and scope

This is the SDK-only developer preview. Its public Node client targets the
existing `merx-atum-resource-v1-draft.1` sandbox profile. It supports
`prices.read`, `order.preview` and `sandbox.execute`. A simulated operation does
not purchase Energy or debit a balance.

The earlier private joined journey used actual owner password/passkey consent,
OAuth-issued code/Device agent tokens, MERX HTTPS/mTLS verification, durable
replay/quotas and sandbox execution. It covered shared quota, revocation, lost
response and MERX service/database restart. Generated accounts/PKI, a virtual
WebAuthn authenticator and controlled clock were explicit test setup. This is
component/integration evidence, not evidence of a public production deployment.

The standalone preview adds a supported public resource-client export and clean
packaging. A fresh run of the joined journey against this new public packaging
has not yet been claimed.

## Hosted developer sandbox

ATUM's site will be the entry point for learning and trying the integration.
The intended journey is passport creation, resource-account connection, agent
registration, explicit owner permission, test invocation, and revocation. MERX
provides the first example resource and its own isolated sandbox backend.

Stable public origins, ordinary browser TLS, persistent deployment and developer
application registration are being prepared. No live registration URL is supplied
in this release. Use a registered development environment for OAuth/network examples;
the bundled offline verification example is immediately reproducible.

## Separate product work

Real Energy purchases need a separate signed monetary action, exact all-in caps,
provider/order recovery and owner consent. Native phone enrollment and physical
sensor evidence, a public agent status/read policy, and Galactica certificates
are also separate work. Web account/passkey authentication alone does not establish
physical sensor consistency or unique human identity.

The server-side engine is not part of this repository. Hosting and service access
have their own configuration and terms; the SDK license concerns the code here.

## Standalone preview checks

The clean workspace installation passed 304 package tests (80 Agent, 29 replay
unit and 195 verification), TypeScript 5.9.3 checks, and the offline proof/replay
example. Package inventories contain runtime files, declarations where supplied,
replay migrations and license/docs, with no test keys or private server files.
These are SDK/package checks; the separate PostgreSQL restart and joined browser
evidence above is retained at its original tested revisions.
