import { createCurrentAuthorizationVerifier } from '@atum/verification/current-authorization';
import { createNonceChallengeVerifier, VerificationError } from '@atum/verification/nonce-challenge';
import { createUsageStore } from './usage-store.mjs';

const MAX_BODY = 32 * 1024;
function fail(code, status = 400) { const error = new Error(code); error.code = code; error.status = status; throw error; }
function wireHeaders(req, endpoint) {
  const values = new Map();
  for (let index = 0; index < req.rawHeaders.length; index += 2) {
    const name = req.rawHeaders[index].toLowerCase();
    const list = values.get(name) ?? []; list.push(req.rawHeaders[index + 1]); values.set(name, list);
  }
  for (const name of ['host', 'authorization', 'dpop', 'content-type', 'content-length', 'transfer-encoding']) {
    if ((values.get(name)?.length ?? 0) > 1) fail('invalid_request');
  }
  const expected = new URL(endpoint.url);
  if (values.get('host')?.[0] !== expected.host || !values.get('authorization')?.[0]
      || !values.get('dpop')?.[0] || values.get('content-type')?.[0] !== 'application/json'
      || values.has('transfer-encoding') || values.has('expect')) fail('invalid_request');
  const length = values.get('content-length')?.[0];
  if (typeof length !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(length)
      || Number(length) > MAX_BODY) fail('invalid_request');
  return { authorization: values.get('authorization')[0], dpop: values.get('dpop')[0], length: Number(length) };
}
function parameters(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).length !== 2 || typeof value.calendar_id !== 'string'
      || !/^[A-Za-z0-9._:-]{1,128}$/.test(value.calendar_id)
      || !Number.isSafeInteger(value.limit) || value.limit < 1 || value.limit > 100) fail('invalid_calendar_request');
  return value;
}

export async function createCalendarResource({ authorization, pool, endpoint }) {
  const verifier = await createCurrentAuthorizationVerifier(authorization);
  const challengeVerifier = await createNonceChallengeVerifier({ registration: authorization.registration,
    ...(Object.hasOwn(authorization, 'descriptor') ? { descriptor: authorization.descriptor } : {}),
    issuerKeys: authorization.proof.issuerKeys, endpoint: authorization.proof.endpoint,
    clock: authorization.clock });
  const usage = createUsageStore(pool, { clock: authorization.clock });
  return Object.freeze({ async handle(req, res) {
    try {
      if (req.method !== endpoint.method || req.url !== new URL(endpoint.url).pathname) fail('not_found', 404);
      const headers = wireHeaders(req, endpoint);
      const chunks = []; let size = 0;
      for await (const chunk of req) { size += chunk.length; if (size > MAX_BODY) fail('invalid_request'); chunks.push(chunk); }
      const body = Buffer.concat(chunks);
      if (body.length !== headers.length) fail('invalid_request');
      const protectedRequest = { authorization: headers.authorization,
        dpop: headers.dpop, body, method: req.method, url: endpoint.url };
      let current;
      try { current = await verifier.verifyCurrent(protectedRequest); }
      catch (error) {
        if (!(error instanceof VerificationError) || error.code !== 'invalid_proof') throw error;
        const verified = await challengeVerifier.verifyNonceChallengeRequest(protectedRequest,
          { deadlineAt: performance.now() + Math.min(5_000, authorization.authority.timeoutMs) });
        const issued = await authorization.proof.replayStore.issueNonce({
          agent_key_thumbprint: verified.agent_key_thumbprint });
        const bytes = Buffer.from(JSON.stringify({ error: 'use_dpop_nonce' }));
        res.writeHead(401, { 'content-type': 'application/json', 'content-length': String(bytes.length),
          'cache-control': 'no-store', 'www-authenticate': 'DPoP error="use_dpop_nonce", algs="ES256"',
          'dpop-nonce': issued.nonce }); res.end(bytes); return;
      }
      if (current.action_request.action !== 'calendar.event.read') fail('action_not_supported', 422);
      const input = parameters(current.action_request.parameters);
      const accepted = await usage.acceptAndRun({ context: current.context, admission_id: current.admission_id,
        intent_hash: current.intent_hash, client_id: current.client_id,
        action_request: current.action_request, permissions: current.permissions,
        grant_limit: current.grant_limit, token_expires_at_ms: current.token_expires_at_ms,
        grant_expires_at_ms: current.grant_expires_at_ms,
        snapshot_valid_until_ms: current.snapshot_valid_until_ms,
        acceptance_expires_at_ms: current.acceptance_expires_at_ms,
        first_submit_expires_at_ms: current.first_submit_expires_at_ms }, async connection => {
        const rows = await connection.query(`SELECT event_id,title,starts_at_ms FROM calendar_events
          WHERE scoped_subject=$1 AND calendar_id=$2 ORDER BY starts_at_ms,event_id LIMIT $3`,
        [current.scoped_subject, input.calendar_id, input.limit]);
        return { events: rows.rows };
      });
      const bytes = Buffer.from(JSON.stringify({ permission_checked: true,
        resource_acceptance: accepted.replayed ? 'replayed' : 'accepted', result: accepted.result }));
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(bytes.length), 'cache-control': 'no-store' }); res.end(bytes);
    } catch (error) {
      const code = typeof error?.code === 'string' ? error.code : 'temporarily_unavailable';
      const status = error?.status ?? (code === 'grant_limit_exhausted' ? 409 : code === 'temporarily_unavailable' ? 503 : 400);
      const bytes = Buffer.from(JSON.stringify({ error: { code } }));
      res.writeHead(status, { 'content-type': 'application/json', 'content-length': String(bytes.length), 'cache-control': 'no-store' }); res.end(bytes);
    }
  }, close: () => verifier.close() });
}
