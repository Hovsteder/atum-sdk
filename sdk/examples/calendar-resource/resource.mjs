import { createProtectedHttpHandler } from '@atum/verification/node-http';
import { createUsageStore } from './usage-store.mjs';

function parameters(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).length !== 2 || typeof value.calendar_id !== 'string'
      || !/^[A-Za-z0-9._:-]{1,128}$/.test(value.calendar_id)
      || !Number.isSafeInteger(value.limit) || value.limit < 1 || value.limit > 100) { const error = new Error('invalid_request'); error.code = 'invalid_request'; throw error; }
  return value;
}

export async function createCalendarResource({ authorization, pool, endpoint }) {
  const usage = createUsageStore(pool, { clock: authorization.clock });
  return createProtectedHttpHandler({ authorization, endpoint, async onAuthorized(current) {
      if (current.action_request.action !== 'calendar.event.read') { const error = new Error('action_not_supported'); error.code = 'action_not_supported'; throw error; }
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
      return { permission_checked: true, resource_acceptance: accepted.replayed ? 'replayed' : 'accepted', result: accepted.result };
  } });
}
