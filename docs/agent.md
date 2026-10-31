# Connect an agent to its owner's permission

An agent uses its own P-256 key. Its owner's private key stays with the owner.
The owner reviews the requested actions, limit and expiry and authorizes the
agent through ATUM. Presenting somebody else's public passport URL is not proof
of that authorization.

Obtain trusted service/client configuration from the connected service. Choose
Device flow for a command-line or headless agent, or authorization-code flow for
an application with a registered HTTPS return address. Device-only clients do
not need a fabricated return address. Authorization-code flow uses exact
registered callbacks and PKCE.

1. Prepare a request for the service's registered permission names.
2. Let the owner complete the actual ATUM consent flow.
3. Exchange the approved request for an issued DPoP-bound token.
4. Persist the operation identity and action parameters before sending work.
5. Sign the resource request with the same agent key and complete its nonce
   challenge without changing the original body/context.
6. Keep the observed result with that operation. An uncertain result is not
   permission to create and submit a replacement operation.

Use the [Agent API](../sdk/packages/agent/README.md) and the
[independent service example](../sdk/examples/calendar-resource/README.md).
The generic signing API works with registered service-owned actions and does not
prescribe your service's result format. The existing MERX invocation client is a
separate compatibility API with its own closed result schema.

Refresh remains subject to current permission, service/client lifecycle and
revocation. A service's API credential cannot grant an agent permission. Owner
revocation stops new authorized work; it is not a claim that a previously
accepted external operation can be undone.

Keep tokens, refresh state and private keys secret. Verify TLS certificates and
hostnames. Close clients when finished; local timeout/close cannot cancel work
already accepted by a remote service. Persist operation identity across process
restarts instead of relying only on an in-memory request fence.

Web passkey authorization proves this owner's approval under the selected policy.
Native phone enrollment and physical sensor-history evidence are separate layers;
a successful web login is not labeled as physical-history verification.
