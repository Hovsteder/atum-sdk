#!/usr/bin/env node
import { createPrivateKey, generateKeyPairSync, randomBytes, sign as nodeSign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import https from 'node:https';

import { createAgentClient, createAgentKey } from '@atum/agent';
import { createProtectedRequestSigner } from '@atum/agent/resource-proof';
import { actionHash, parseStrictJson } from '@atum/verification/context';
import { createObservedClock } from './observed-clock.mjs';

const required = name => { const value = process.env[name]; if (!value) throw new Error(`missing ${name}`); return value; };
const exact = (value, fields) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).length === fields.length
  && fields.every(field => Object.hasOwn(value, field));

function post(material, ca) {
  const url = new URL(material.url); const body = Buffer.from(material.body, 'utf8');
  return new Promise((resolve, reject) => {
    const request = https.request(url, { method: material.method, ...(ca === undefined ? {} : { ca }), servername: url.hostname,
      headers: { host: url.host, authorization: material.authorization, dpop: material.dpop,
        'content-type': 'application/json', 'content-length': String(body.length) } }, response => {
      const chunks = []; let size = 0;
      response.on('data', chunk => { size += chunk.length; if (size > 65_536) request.destroy(new Error('resource response too large')); else chunks.push(chunk); });
      response.on('end', () => {
        try {
          const length = response.headers['content-length'];
          if (response.headers.location || response.headers['transfer-encoding'] || !/^(?:0|[1-9][0-9]*)$/.test(length ?? '')) throw new Error('invalid resource response');
          const bytes = Buffer.concat(chunks); if (Number(length) !== bytes.length) throw new Error('invalid resource response');
          resolve({ status: response.statusCode, headers: response.headers, body: JSON.parse(bytes.toString('utf8')) });
        } catch (error) { reject(error); }
      });
    });
    request.setTimeout(5_000, () => request.destroy(new Error('resource request timed out')));
    request.once('error', reject); request.end(body);
  });
}

function tokenPayload(token) {
  if (typeof token !== 'string' || token.length > 16_384) throw new Error('invalid access token');
  const parts = token.split('.'); if (parts.length !== 3) throw new Error('invalid access token');
  const value = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  if (!value || typeof value !== 'object' || Array.isArray(value) || !value.atum || !value.cnf) throw new Error('invalid access token');
  return value;
}

const agentConfiguration = parseStrictJson(await readFile(required('ATUM_AGENT_CONFIG_FILE')), 65_536);
if (!exact(agentConfiguration, ['registry', 'resource_endpoint'])
    || !exact(agentConfiguration.resource_endpoint, ['method', 'url'])
    || agentConfiguration.resource_endpoint.method !== 'POST') throw new Error('invalid public Agent configuration');
const issuerCa = process.env.ATUM_ISSUER_CA_FILE ? await readFile(process.env.ATUM_ISSUER_CA_FILE, 'utf8') : undefined;
const resourceCa = process.env.ATUM_CALENDAR_CA_FILE ? await readFile(process.env.ATUM_CALENDAR_CA_FILE, 'utf8') : undefined;
const clock = createObservedClock(required('ATUM_CLOCK_OBSERVATION_FILE'), {
  maxAgeMs: Number(process.env.ATUM_CLOCK_MAX_AGE_MS ?? '1000') });
const registry = agentConfiguration.registry; const descriptor = registry?.descriptor;
if (!exact(registry, ['registration', 'descriptor', 'clients']) || !Array.isArray(registry.clients)) throw new Error('invalid service registration');
const client = registry.clients.find(value => value?.flows?.includes('device_code') && value?.permissions?.includes('calendar.event.read'));
if (!client) throw new Error('calendar Device client is not registered');

const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const publicJwk = pair.publicKey.export({ format: 'jwk' });
const privateKey = createPrivateKey({ key: pair.privateKey.export({ format: 'jwk' }), format: 'jwk' });
const key = await createAgentKey({ publicJwk, timeoutMs: 5_000,
  sign: input => nodeSign('sha256', input, { key: privateKey, dsaEncoding: 'ieee-p1363' }) });
const issuer = registry.registration.issuer;
const agent = await createAgentClient({ registration: registry.registration, descriptor, client,
  endpoints: { options_url: `${issuer}/atum/request/options`, verify_url: `${issuer}/atum/request/verify`,
    par_url: `${issuer}/request`, authorization_url: `${issuer}/auth`,
    device_authorization_url: `${issuer}/device/auth`, token_url: `${issuer}/token` },
  tls: issuerCa === undefined ? {} : { ca: issuerCa }, key, clock, timeoutMs: 5_000, maxConcurrent: 2 });
try {
  const sample = clock(); if (sample.healthy !== true) throw new Error('observed clock is unhealthy');
  const lifetime = Math.min(client.max_grant_lifetime_ms, 240_000);
  const flow = await agent.beginDeviceAuthorization({ permissions: [{ action: 'calendar.event.read' }],
    grant_limit: Math.min(client.max_grant_limit, 2), grant_expires_at_ms: sample.now_ms + lifetime });
  process.stdout.write(`Open ${flow.verification_uri} and enter ${flow.user_code}.\n`);
  const controller = new AbortController(); process.once('SIGINT', () => controller.abort());
  const token = await flow.poll({ signal: controller.signal });
  const payload = tokenPayload(token.access_token); const claims = payload.atum;
  if (payload.iss !== issuer || payload.aud !== registry.registration.audience || payload.client_id !== client.client_id
      || typeof payload.sub !== 'string' || payload.cnf.jkt !== key.thumbprint) throw new Error('access token context mismatch');
  const actionRequest = { action: 'calendar.event.read', parameters: {
    calendar_id: process.env.ATUM_CALENDAR_ID ?? 'main', limit: Number(process.env.ATUM_CALENDAR_LIMIT ?? '10') } };
  const context = { protocol_version: '0.1.0-draft.2', resource_profile_version: claims.resource_profile_version,
    resource_profile_hash: claims.resource_profile_hash, issuer: payload.iss, audience: payload.aud,
    environment: claims.environment, tenant_id: claims.tenant_id, resource_id: claims.resource_id,
    quota_scope_id: claims.quota_scope_id, operation_namespace: claims.operation_namespace,
    scoped_subject: payload.sub, operation_id: randomBytes(32).toString('base64url'), grant_id: claims.grant_id,
    grant_version: claims.grant_version, policy_version: claims.policy_version, agent_key_thumbprint: payload.cnf.jkt,
    consent_hash: claims.consent_hash, action_hash: actionHash(actionRequest, descriptor),
    account_binding_id: claims.account_binding_id, account_binding_version: claims.account_binding_version,
    action: actionRequest.action };
  const endpoint = agentConfiguration.resource_endpoint;
  let signer = createProtectedRequestSigner({ key, registration: registry.registration, descriptor, endpoint, clock, timeoutMs: 5_000 });
  const input = { access_token: token.access_token, context, action_request: actionRequest };
  const challenge = await post(await signer.signChallenge(input), resourceCa);
  const nonce = challenge.headers['dpop-nonce'];
  if (challenge.status !== 401 || !exact(challenge.body, ['error']) || challenge.body.error !== 'use_dpop_nonce'
      || typeof nonce !== 'string') throw new Error('resource nonce challenge rejected');
  signer = createProtectedRequestSigner({ key, registration: registry.registration, descriptor, endpoint, clock, timeoutMs: 5_000 });
  const response = await post(await signer.sign({ ...input, nonce }), resourceCa);
  if (response.status !== 200) throw new Error('calendar operation rejected');
  process.stdout.write(`${JSON.stringify(response.body)}\n`);
} catch {
  process.exitCode = 1;
  process.stderr.write('ATUM authorization or operation was not confirmed. Do not resubmit an attempted operation automatically.\n');
} finally { await agent.close(); }
