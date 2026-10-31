# Changelog

## 0.1.0-rc.2 — 2026-10-31

- Generic registered service action names and canonical JSON parameters, separate
  from the preserved MERX compatibility profiles.
- Current-authorization composition joins request proof, durable replay and live
  signed authority; service acceptance and business results remain separate.
- Explicit scoped-service-credential HTTPS transport and Device-only clients
  without a fabricated callback.
- Independent runnable calendar service and Device Agent, plus self-service
  registration, credential rotation and disable documentation.
- Repeatable replay migration validates the installed catalog, upgrades exact v1
  and rejects schema drift.
- Matching public Agent, Verification and PostgreSQL replay packages. Public
  API hosting, native Passport SDK and live Energy rollout remain separate.

## 0.1.0-rc.1 — 2026-10-31

- First standalone SDK-only source distribution under Apache-2.0.
- Public typed Agent resource client for the existing MERX sandbox nonce/invoke
  profile, with strict result binding and process-local duplicate-operation fencing.
- OAuth code/Device and refresh, verification/authority clients and PostgreSQL
  replay components, with tests, migration files and integration documentation.
- Hosted public sandbox, npm registry publication and monetary execution remain
  separate release milestones.
