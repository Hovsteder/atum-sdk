# ATUM SDK

Connect a software agent to owner-approved permissions, and verify its requests
at your service. ATUM's SDK provides OAuth agent clients, request and authority
verification, and durable PostgreSQL replay protection.

**Developer preview: 0.1.0-rc.1.** The first supported integration profile is the
MERX sandbox. Public hosted onboarding is being prepared; this repository does
not deploy an issuer or create a live passport by itself. See [release status](docs/status.md).

## Try the code

Requirements: Node.js 22.12+, npm, and OpenSSL for local HTTPS tests.

```sh
git clone --branch v0.1.0-rc.1 https://github.com/Hovsteder/atum-sdk.git
cd atum-sdk
npm ci --ignore-scripts --no-audit --no-fund
npm run example:verify
npm run test:types
```

The verification example uses a bundled synthetic signed request and demonstrates
both signature verification and replay rejection. Its output explicitly grants
no execution authority. No account, funds, live service or private server source
is needed for this example.

## Choose your integration

| You are building | Start here |
| --- | --- |
| An agent acting with its owner's permission | [Agent quickstart](docs/agent.md), [Agent API](sdk/packages/agent/README.md) |
| A service that accepts ATUM agents | [Resource integration](docs/resource.md), [verification API](sdk/packages/verification/README.md) |
| Persistent nonce/replay protection | [PostgreSQL adapter](sdk/packages/replay-postgres/README.md) |
| An application that needs passport creation and agent management | [Hosted sandbox and owner flow](docs/status.md) |

The public sandbox is ATUM's developer environment, with an entry point planned
on `atum.digital`. MERX is the first reference service behind it. Developers
will be able to create a passport, authorize their own agent, try a request,
inspect the result, and revoke permission. SDK users can then implement the same
resource-side boundaries in their own service.

## Packages

| Package | Role |
| --- | --- |
| `@atum/agent` | P-256 signing port, owner request preparation, OAuth code/Device flows, token refresh, nonce/invoke HTTPS client and TypeScript declarations |
| `@atum/verification` | Issuer tokens and DPoP, complete intent binding, signed grant/admission checks, mTLS authority and owner-connector clients |
| `@atum/replay-postgres` | Atomic nonce consumption and proof replay protection, with migrations |

Use the workspace installation above for this preview. npm registry publication
is a separate release step; do not assume these names are available there.
The package tarballs contain runtime files and documentation, not server code
or test private keys. To add the packages to an existing application, download
all three `.tgz` files from the matching [GitHub release](https://github.com/Hovsteder/atum-sdk/releases/tag/v0.1.0-rc.1),
then install them together from their download directory:

```sh
npm install ./atum-agent-0.1.0-rc.1.tgz ./atum-verification-0.1.0-rc.1.tgz ./atum-replay-postgres-0.1.0-rc.1.tgz
```

The tarballs use matching exact package versions. A standalone application
installation and ESM/CommonJS public imports are checked before release.

## Security and lifecycle

A valid request proof is not permission to execute. A resource also checks current
grant/binding policy, reserves quota, obtains admission, and durably claims the
original operation. A network timeout cannot undo a submitted operation. The
client performs one nonce continuation and does not retry uncertain business work
or invent a new operation ID. See [resource responsibilities](docs/resource.md).

SDK source is licensed under [Apache-2.0](LICENSE). The ATUM server-side
sensor-consistency engine, hosted-service credentials and private project history
are outside this repository. [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md).
