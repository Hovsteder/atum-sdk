# Self-contained Node quickstart

Supported reference platform: Node 22.12 or newer on Linux, a local `chronyd`, and PostgreSQL.
Install the published packages and copy `sdk/examples/calendar-resource` as a starting point; it is a reference service, not a hosted ATUM runtime.

1. Run PostgreSQL and set `ATUM_CALENDAR_DATABASE_URL`; run `npm run migrate` once. The migration only creates the example tables and never drops data.
2. Create a local development CA and an HTTPS certificate whose SAN exactly names the public `ATUM_CALENDAR_ENDPOINT`. Set `ATUM_CALENDAR_TLS_KEY_FILE`, `ATUM_CALENDAR_TLS_CERT_FILE`, and the matching CA files for the Agent and Passport. Do not disable certificate verification.
3. Start the independent observer: `ATUM_CLOCK_OBSERVATION_FILE=/absolute/clock.json ATUM_CHRONYC_PATH=/usr/bin/chronyc ATUM_CHRONYC_PORT=3231 atum-clock`. The observer uses local chronyd only. Normal leap status, stratum 1–15, reference age (default maximum 300 seconds), and a combined uncertainty of at most 1000 ms are required. The sample reader refuses observations older than `ATUM_CLOCK_MAX_AGE_MS` (default 1000 ms) and rejects a wall-clock step from the observed monotonic projection.
4. Set the service-access, Passport, database, TLS, clock and endpoint environment values, then run `npm start`. It listens on `127.0.0.1:8443` by default; use `ATUM_CALENDAR_LISTEN_HOST` and `ATUM_CALENDAR_LISTEN_PORT` to select the local listener. These do not change the registered public endpoint.
5. Export public Agent configuration with `npm run export-agent-config -- /absolute/agent-config.json`, set an absolute private `ATUM_AGENT_STATE_DIR`, then run `npm run authorize`. Complete Passport consent. `npm run agent -- status` shows only safe state.

An authorized empty event list is a successful query. The example does not seed owners, consents, grants, or synthetic events.
