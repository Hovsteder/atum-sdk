# Connect your first service

This walkthrough uses the **public ATUM hosts**, the published SDK and a local
calendar service. You register your service, approve an agent with your passkey,
then verify requests at your own backend. No MERX account or private ATUM code is
required. The empty calendar is intentional: `events: []` is a valid successful
query. Replace its data access with your application's own logic afterward.

Supported reference environment: **Linux, Node.js 22.12+, npm, Docker, OpenSSL,
and a synchronized local chronyd**. Your browser must support passkeys. The SDK
can be used in other Node applications; this exact walkthrough has these hosting
requirements. An HTTP reverse proxy that terminates TLS is not supported by the
reference handler; see [hosting](node-hosting.md).

## 1. Install the matching source

```bash
git clone --branch v0.1.0-rc.3 https://github.com/Hovsteder/atum-sdk.git
cd atum-sdk
npm ci --ignore-scripts --no-audit --no-fund
cd sdk/examples/calendar-resource
export ATUM_DEMO_DIR="$(mktemp -d /tmp/atum-calendar.XXXXXX)"
chmod 700 "$ATUM_DEMO_DIR"
```

Keep this terminal open: later commands use its variables. The directory contains
credentials and Agent keys; do not commit, share, or copy it into a public image.
For a persistent deployment, use a backed-up private directory and database.

## 2. Prepare your resource's database and TLS

This creates a **new local database**, unrelated to ATUM's databases. Port 55432
must be free. Keep the password and container name for later maintenance.

```bash
export ATUM_DEMO_PG_PASSWORD="$(openssl rand -hex 24)"
export ATUM_DEMO_PG_CONTAINER="atum-calendar-$(openssl rand -hex 4)"
docker run -d --name "$ATUM_DEMO_PG_CONTAINER" \
  -e POSTGRES_PASSWORD="$ATUM_DEMO_PG_PASSWORD" -e POSTGRES_DB=atum_calendar \
  -p 127.0.0.1:55432:5432 \
  -v "$ATUM_DEMO_DIR/postgres:/var/lib/postgresql/data" postgres:16
until docker exec "$ATUM_DEMO_PG_CONTAINER" pg_isready -U postgres -d atum_calendar; do sleep 1; done
export ATUM_CALENDAR_DATABASE_URL="postgresql://postgres:$ATUM_DEMO_PG_PASSWORD@127.0.0.1:55432/atum_calendar"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj '/CN=Local ATUM example CA' \
  -keyout "$ATUM_DEMO_DIR/ca.key" -out "$ATUM_DEMO_DIR/ca.pem"
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=localhost' \
  -keyout "$ATUM_DEMO_DIR/resource.key" -out "$ATUM_DEMO_DIR/resource.csr"
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "$ATUM_DEMO_DIR/tls.ext"
openssl x509 -req -in "$ATUM_DEMO_DIR/resource.csr" \
  -CA "$ATUM_DEMO_DIR/ca.pem" -CAkey "$ATUM_DEMO_DIR/ca.key" -CAcreateserial \
  -days 2 -extfile "$ATUM_DEMO_DIR/tls.ext" -out "$ATUM_DEMO_DIR/resource.pem"
chmod 600 "$ATUM_DEMO_DIR"/*.key
export ATUM_CALENDAR_TLS_KEY_FILE="$ATUM_DEMO_DIR/resource.key"
export ATUM_CALENDAR_TLS_CERT_FILE="$ATUM_DEMO_DIR/resource.pem"
export ATUM_CALENDAR_CA_FILE="$ATUM_DEMO_DIR/ca.pem"
export ATUM_CALENDAR_ENDPOINT=https://localhost:8443/v1/atum/operations
export ATUM_CALENDAR_LISTEN_HOST=127.0.0.1
export ATUM_CALENDAR_LISTEN_PORT=8443
```

Only the Agent trusts this temporary CA for **your local resource**. The public
Passport, issuer and Verify API use normal public certificate validation; do not
set `ATUM_ISSUER_CA_FILE` or `ATUM_SERVICE_ACCESS_CA_FILE` for those hosts. The
browser does not need to visit the local resource.

## 3. Start measured time observations

Install/configure chrony on the Linux host if it is not already present (for
example, your distribution's `chrony` package). First verify `chronyc tracking`
reports `Leap status: Normal`. The SDK does not change the system clock.

```bash
export ATUM_CLOCK_OBSERVATION_FILE="$ATUM_DEMO_DIR/clock.json"
export ATUM_CHRONYC_PATH=/usr/bin/chronyc
export ATUM_CHRONYC_PORT=323
../../../node_modules/.bin/atum-clock > "$ATUM_DEMO_DIR/clock.log" 2>&1 &
export ATUM_DEMO_CLOCK_PID=$!
```

Use the actual absolute chronyc binary path and local command port if yours
are different. The observer checks stratum, reference age (default 300 seconds),
clock steps and combined uncertainty (at most 1000 ms). Readers reject stale
observations after 1000 ms by default. An unsynchronized or unavailable observer
fails closed; do not replace it with `healthy: true` or a static JSON example.
The observer and consumer must run on the same host/monotonic clock.

## 4. Register your service and start its backend

Open [Passport developer](https://passport.atum.digital/developer). Create your
passport and sign in with your passkey if needed. Connect a service with:

- Name: your service name, such as “My calendar”.
- Origin: `https://localhost:8443` for this local walkthrough.
- Permission: `calendar.event.read`.
- Device flow enabled (the portal's default clients include it).

Copy the service credential when shown. It belongs only to your backend.
Entering an origin registers configuration; it does not prove domain ownership.

```bash
export ATUM_SERVICE_ACCESS_URL=https://verify.atum.digital
read -r -s -p 'Paste service credential: ' ATUM_SERVICE_CREDENTIAL; printf '\n'
export ATUM_SERVICE_CREDENTIAL
npm run migrate
npm run export-agent-config -- "$ATUM_DEMO_DIR/agent-config.json"
export ATUM_AGENT_CONFIG_FILE="$ATUM_DEMO_DIR/agent-config.json"
export ATUM_AGENT_STATE_DIR="$ATUM_DEMO_DIR/agent"
npm start > "$ATUM_DEMO_DIR/resource.log" 2>&1 &
export ATUM_DEMO_RESOURCE_PID=$!
```

Wait for `calendar resource listening` in `resource.log`. The exported Agent
configuration contains public registration data, not the service credential.
Only your backend needs PostgreSQL access and the service credential; a separate
Agent machine needs the public config, its own private state, the resource CA
(for this development certificate), and its own measured clock.

## 5. Approve and use an agent

```bash
npm run authorize
```

Open the printed `https://auth.atum.digital/device` address, enter its code, open
Passport from that page, approve the displayed permission with your passkey, then
finish the Device flow. The command saves the agent's key and issued tokens in
its private state directory. This example requests two uses for at most four
minutes; the registry may apply lower limits.

```bash
npm run agent -- status
npm run agent -- invoke first-calendar-read
# A new process with the same label returns its saved observation: no HTTP replay.
npm run agent -- invoke first-calendar-read
# Explicit token rotation keeps the same agent key and original grant.
npm run agent -- refresh
npm run agent -- invoke second-calendar-read
```

The first success includes `permission_checked: true` and `result.events`.
The service applies its own durable use limit after ATUM verifies current
permission. Request labels are permanent identifiers in this Agent state:
changing parameters under an old label is refused. An ambiguous network result
is retained as unresolved; repeating the label **does not send it again**.
An interrupted refresh also cannot reuse its one-time refresh token.

In the Passport consent page choose revoke and confirm with your passkey. Then:

```bash
npm run agent -- invoke after-revoke
```

It must be denied. A new operation label is necessary here: reading a saved old
result is historical local state and does not perform a fresh permission check.

See [Agent state and recovery](agent.md) before moving this example into a
persistent service. After a killed Agent process, remove a stale `.lock` only
after independently confirming no process uses that state; retain its journal
and all unresolved operations. Never delete state to retry an unknown operation.

## 6. Stop the local example

Revoke the grant and disable the test service in Passport when finished. Keep
private state if it is still needed for diagnosis or recovery.

```bash
kill "$ATUM_DEMO_RESOURCE_PID" "$ATUM_DEMO_CLOCK_PID"
wait "$ATUM_DEMO_RESOURCE_PID" "$ATUM_DEMO_CLOCK_PID"
docker stop "$ATUM_DEMO_PG_CONTAINER"
```

These commands stop the processes and database; they do not delete stored state.

## Automated public acceptance

`scripts/hosted-acceptance.py --run` automates this journey with a virtual CTAP2
passkey, a fresh private PostgreSQL cluster and localhost TLS. It uses only this
repository and the public hosts. It additionally verifies a transparent TCP
forwarder, Agent process reuse without a duplicate request, a resource/database
restart, token refresh, and an actual invocation after revocation.

Install Python Playwright and its Chromium, and PostgreSQL 16 client/server
binaries. Use `ATUM_TEST_PG_BIN` if they are outside `/usr/lib/postgresql/16/bin`.
The script accepts `ATUM_TEST_CHROMIUM` for an installed Chromium. It never uses
an existing database URL. `--run` creates a real test passport/service whose public
audit remains; temporary keys, processes and database are cleaned up. The safe
`--report` JSON contains no credential, token, private key or browser session.
