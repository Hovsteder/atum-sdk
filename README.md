# ATUM SDK

The public Node reference kit includes a local chrony observer, a direct-TLS protected HTTP boundary, a PostgreSQL-backed calendar example and a durable Device Agent workflow. Start with [docs/quickstart.md](docs/quickstart.md).

Verify an agent's connection to its owner's passport and the owner's permission
at your service. An agent obtains owner-approved access, signs each request with
its own key, and your backend checks that permission through ATUM before applying
its own rules.

A developer connects an existing service and chooses its action names. A calendar
can use `calendar.event.read`; a document service can use `document.read`. MERX is
the first reference integrator. Its Energy, pricing and order rules belong to its
adapter and are not prerequisites for another service.

**Developer preview: 0.1.0-rc.3.** See [release status](docs/status.md) for the exact published
version, local acceptance evidence and hosted API availability. The SDK repository
does not contain the private ATUM server or create an owner's permission by itself.

## Start here

| Your integration | Guide |
| --- | --- |
| Accept agents at an existing service | [Resource guide](docs/resource.md) and [calendar example](sdk/examples/calendar-resource/README.md) |
| Register and manage a service | [Self-service setup](docs/service-registration.md) |
| Connect an agent to owner approval | [Agent guide](docs/agent.md) and [Agent API](sdk/packages/agent/README.md) |
| Verify current passport/permission policy | [Verification API](sdk/packages/verification/README.md) |
| Store nonce and replay state durably | [PostgreSQL adapter](sdk/packages/replay-postgres/README.md) |
| Understand hosted registration and separate native evidence | [Status and scope](docs/status.md) |

An integrator's service credential authenticates the service to ATUM. The owner
separately approves the agent's actions, limit and expiry. Neither a developer
login, a service credential nor a public passport URL substitutes for that consent.

## Packages

| Package | Role |
| --- | --- |
| `@atum/agent` | P-256 signing, owner-request preparation, OAuth code/Device flows, DPoP-bound tokens and request proofs |
| `@atum/verification` | Registered action/context validation, token/DPoP verification and current signed authority checks |
| `@atum/replay-postgres` | Durable nonce issuance/consumption and proof replay protection |

Requirements: Node.js 22.12+, npm, and OpenSSL for local HTTPS tests. Clone the
matching release tag, then install the workspace:

```sh
git clone --branch v0.1.0-rc.3 https://github.com/Hovsteder/atum-sdk.git
cd atum-sdk
npm ci --ignore-scripts --no-audit --no-fund
npm run example:verify
npm run test:types
```

The offline verification example uses a public synthetic fixture. It demonstrates
signature and replay checks and explicitly grants no execution authority. The
calendar example shows the separate current-authorization and service-acceptance
steps using an operator-provided ATUM host and issued tokens. The hosted entry is
[atum.digital/developers](https://atum.digital/developers): create or sign in to
[Passport](https://passport.atum.digital/), then register a service at
[Passport developer](https://passport.atum.digital/developer). The issuer is
`https://auth.atum.digital` and the service API is `https://verify.atum.digital`.

For an existing application, install the matching package tarballs from the
[GitHub releases](https://github.com/Hovsteder/atum-sdk/releases). Install all three
matching files together. npm registry publication is a separate step; package
names in this guide do not claim they are available on npm.

## Boundaries

A valid signature is not owner permission. Use the current authorization API to
check the issued grant and its current policy; use your own service to enforce
business parameters, data ownership, usage and operation recovery. Verification
never means an external operation has completed.

Generic permissions authorize registered action names. Unsupported restriction
fields reject rather than disappear. Existing MERX profiles remain explicit
compatibility paths: a generic permission does not loosen an old exact-quote
purchase grant.

Web passkey consent and physical phone-history evidence are distinct. This public
SDK does not ship the native Passport collection SDK or the server-side sensor
consistency engine. Consult [status](docs/status.md) before relying on a particular
evidence policy.

Licensed under [Apache-2.0](LICENSE). [Contributing](CONTRIBUTING.md) ·
[Security](SECURITY.md).
