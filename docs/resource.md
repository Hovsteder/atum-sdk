# Accept ATUM agents at your service

The [verification package](../sdk/packages/verification/README.md) checks tokens,
DPoP proofs and the complete registered context. The [PostgreSQL adapter](../sdk/packages/replay-postgres/README.md)
provides durable nonce/replay storage. The [authority contract](../sdk/authority/CONTRACT.md)
defines signed status, admission and retrieval semantics.

## Host boundaries

Your HTTP layer must retain the raw request boundary: fixed trusted URL/method,
strict duplicate-header and JSON checks, bounded bodies, TLS and exact client
registration. Proxy forwarding or a generic JSON middleware must not silently
change the bytes and identity seen by proof verification.

The execution path is:

1. Issue a bound nonce only after the nonce-omitted proof passes. A challenge does
   not reserve business quota or authorize an effect.
2. Verify the continued proof and atomically consume its nonce/replay identity.
3. Verify current grant and local account/binding state and reserve common and
   per-grant quota in your durable ledger.
4. Obtain and verify the signed admission. Persist its exact original context,
   decision and deadlines under your resource acceptance protocol.
5. Claim submission once, within its original cap, and persist the result.
6. Reconcile uncertain work through its original operation and external reference.

No single verifier call replaces this lifecycle. `proof_verified` has
`authorization_effect: none`; a signed snapshot permits reservation only.
Historical retrieval cannot renew a permit or establish new read privileges.

Keep authority keys and service mTLS keys in distinct configured roles. Use
measured clock health and retain original caps through waits/transactions. Install
migrations explicitly using dedicated database roles; do not seed accounts or
reset quota on service startup. Bound connection acquisition, concurrency and
error handling as described in the replay profile.

## Examples and verification

`npm run example:verify` verifies one bundled synthetic proof and rejects its
replay using a deliberately local example store. It is an offline teaching tool,
not an HTTP server or production authorization adapter. Production replay uses
the PostgreSQL component and production execution needs the steps above.

MERX is the first integrated reference resource. Its real purchase action and
permanent public deployment are separate from the existing simulation profile.
The SDK preview does not provide a turnkey production resource server.
