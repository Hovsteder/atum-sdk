# Node HTTPS hosting boundary

`createProtectedHttpHandler` is mounted directly on an `node:https` server before any body parser. It accepts an exact registered HTTPS POST endpoint, rejects duplicate or ambiguous framing, requires direct encrypted sockets, bounds body size and read time, and calls the application only after current permission is verified.

```js
const resource = await createProtectedHttpHandler({ authorization, endpoint, onAuthorized: async currentPermission => {
  // Atomically apply this resource's business acceptance/quota/idempotency here.
  return { ok: true };
} });
https.createServer(tlsOptions, resource.handle);
```

Supported deployment is direct TLS or a transparent TCP/SNI pass-through that preserves the TLS socket. Generic HTTP TLS termination and `X-Forwarded-*` headers are not trusted. `close()` stops new work and waits for tracked request work before closing authority transport.
