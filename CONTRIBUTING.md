# Contributing

Use Node.js 22.12+ and OpenSSL. From the repository root:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm test
npm run test:types
```

PostgreSQL integration checks require Linux, Python 3 and PostgreSQL 16 tools at
`/usr/lib/postgresql/16/bin`. They create and remove their own Unix-socket cluster:

```sh
npm run test:postgres
```

Contributions are under Apache-2.0. Keep changes focused, document public behavior,
and add regression coverage for changed authorization or lifecycle boundaries.
Do not weaken signature/context, consent, replay, quota, revoke, deadline or
uncertain-outcome checks. Keep synthetic test fixtures labelled and never commit
credentials or live user data. Dependency installations use the committed lockfile.
A code review and passing affected checks precede release.
