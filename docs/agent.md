# Build an ATUM agent

Start with the [Agent API](../sdk/packages/agent/README.md) and
[exact configuration](../sdk/packages/agent/PROFILE.md). Use a registered ATUM
environment: trusted issuer/resource configuration, client ID, approved redirect
URI (for code flow), resource account binding, a P-256 signing key and a measured
clock adapter. Obtain these through the environment operator; do not construct
trusted values from a request or a public passport URL.

1. Prepare an owner request with the exact actions, limits and expiry.
2. Present the authorization-code or Device flow to the owner.
3. Obtain the issued DPoP-bound token. Keep tokens and refresh state private.
4. Persist one complete operation context and action before invoking the resource.
5. Use `createProtectedResourceClient` for the nonce challenge and continuation.
6. Persist the observed outcome with that original operation. Handle uncertainty
   through the resource's authorized recovery process.

[The small invocation example](../examples/invoke.mjs) imports only public package
exports. It is a function for your application: its configuration and input must
come from your registered environment and actual authorization flow. It does not
mint a grant, assign a new operation ID or simulate owner consent.

`ResourceInvocationError` exposes safe `code` and `status` only. An unknown,
timeout or malformed response must not cause another purchase under a new ID.
The in-memory client fence lasts only for that client instance. Your host owns
durable operation identity across restarts. There is no public status/read method
in this preview; trusted server recovery is a separate capability.

The resource client uses Node's default CA configuration when `tls` is omitted.
For a development CA, pass the explicit trusted `{tls: {ca: pem}}`; never disable
certificate or hostname checks. Existing issuer OAuth configuration requires its
explicit CA bundle; that is a separate client configuration.

Close clients in `finally`. Close/timeout stops local work but cannot cancel a
request already accepted remotely. Do not log tokens, proofs, callback URLs,
nonces, cookies or key material. Returned resource payloads are application data;
apply your own data-handling policy before logging them.
