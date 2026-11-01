# Connect your service

This is the hosted self-service flow. Begin at
[atum.digital/developers](https://atum.digital/developers), create or sign in to
[Passport](https://passport.atum.digital/), then open
[Passport developer](https://passport.atum.digital/developer).

## Developer setup

1. Sign in to Passport with your passkey and open **Connect your service**.
2. Enter your existing service's name and canonical HTTPS origin, for example
   `https://calendar.example`.
3. Add the action names your service accepts, one per line, for example
   `calendar.event.read`. These names are displayed in the owner's grant request.
4. Choose Device flow for command-line/headless agents. Choose authorization-code
   flow when the agent application has an HTTPS callback; register each exact
   callback. Device-only configuration uses an empty callback list.
5. Connect the service and save the generated service ID, client ID and backend
   credential. The secret is displayed only when created or replaced.

The developer registers a service configuration; ATUM assigns the identifiers
and version. There is no separate project that a developer must create.
Registration does not verify ownership of the entered domain or endorse a
service's name. This initial profile does not require a partner-account link.

## Backend configuration

Keep the service credential on your backend. Use it only with the hosted
service-access HTTPS origin, `https://verify.atum.digital`:

```http
GET /v1/service/registration HTTP/1.1
Host: verify.atum.digital
Authorization: Bearer <service-credential>
```

The response supplies the immutable service registration, action descriptor,
OAuth client configuration, public authority keys, evidence policy and issuer
JWKS URL. The [runnable calendar example](../sdk/examples/calendar-resource/README.md)
loads this configuration and public keys directly. It does not require private
ATUM server files or a developer to copy signing keys from a test fixture.

The service credential and the agent token have different purposes. The former
authenticates a backend to ATUM. The latter comes from an owner-approved grant
and is bound to the agent's key. A backend credential cannot approve a grant or
turn another person's passport link into an authorization.

## Owner approval and verification

The agent requests registered actions, a limit and an expiry. The owner reviews
that request and authorizes it with a passkey. The issued token carries the
service-specific owner identity and grant context. The service checks each
request with the [current-authorization API](resource.md#verify-a-request), then
applies its own data-access and business rules.

Generic permissions contain the action name. Parameter-specific restrictions
must not be added as arbitrary ignored fields: unsupported permission fields
are rejected. The service validates its request parameters and data ownership.

## Manage access

Use the developer entry to return to an owned service, replace its credential or
disable it. Replacement invalidates the old secret; save the new one before
leaving the page. Disabling stops new current authorization and token refresh.
It does not undo work a service has already accepted.

After an uncertain registration or rotation response, inspect the saved service
state. Do not automatically repeat a mutation or assume the missing response
means no change occurred. If a newly generated secret was lost, explicitly
replace it; the server stores only its hash and cannot reveal it again.

The first version limits a developer account to eight service registrations and
keeps descriptors immutable. Changing the action contract requires an explicit
new registration/version rather than silently changing an existing grant.
