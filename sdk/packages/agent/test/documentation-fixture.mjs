import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';

import { actionHash } from '@atum/verification/context';
import { canonical } from '../src/strict.mjs';

const vector = JSON.parse(readFileSync(new URL('../../../protocol/owner-consent/owner-consent-v1.json', import.meta.url)));
const privateJwk = vector.test_private_jwk;
export const publicJwk = Object.freeze({ kty: privateJwk.kty, crv: privateJwk.crv, x: privateJwk.x, y: privateJwk.y });
const privateKey = createPrivateKey({ key: privateJwk, format: 'jwk' });
const publicKey = createPublicKey({ key: publicJwk, format: 'jwk' });
const NOW = 1_700_000_000_123;
const REQUEST_ID = '123e4567-e89b-42d3-a456-426614174000';
const CHALLENGE_ID = '223e4567-e89b-42d3-a456-426614174000';
const REQUEST_NONCE = Buffer.alloc(32, 0x35).toString('base64url');
const DPOP_NONCE = Buffer.alloc(32, 0x41).toString('base64url');
const HANDLE = Buffer.alloc(32, 0x1c).toString('base64url');
const CODE = 'C'.repeat(43);
const ACCESS = `${Buffer.from('{"alg":"RS256"}').toString('base64url')}.${Buffer.from('{"sub":"owner"}').toString('base64url')}.${'A'.repeat(342)}`;
const FIRST_REFRESH = 'R'.repeat(43);
const SECOND_REFRESH = 'S'.repeat(43);

function openssl(directory, ...args) {
  execFileSync('openssl', args, { cwd: directory, stdio: 'ignore' });
}

function certificates() {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'atum-agent-documentation-'));
  writeFileSync(path.join(directory, 'server.ext'), 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n');
  openssl(directory, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem',
    '-days', '1', '-subj', '/CN=atum-agent-documentation-ca');
  openssl(directory, 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'server.key', '-out', 'server.csr',
    '-subj', '/CN=localhost');
  openssl(directory, 'x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
    '-out', 'server.pem', '-days', '1', '-extfile', 'server.ext');
  return {
    directory,
    ca: readFileSync(path.join(directory, 'ca.pem'), 'utf8'),
    cert: readFileSync(path.join(directory, 'server.pem')),
    key: readFileSync(path.join(directory, 'server.key')),
  };
}

function json(response, status, value, extra = {}) {
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    'content-type': 'application/json', 'content-length': String(body.length), 'cache-control': 'no-store', ...extra,
  });
  response.end(body);
}

async function body(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks);
}

function digest(domain, value) {
  return `sha256:${createHash('sha256').update(domain, 'ascii').update(canonical(value), 'utf8').digest('hex')}`;
}

function decodeProof(value) {
  const [header, payload, signature] = value.split('.');
  assert.equal(nodeVerify('sha256', Buffer.from(`${header}.${payload}`), { key: publicKey, dsaEncoding: 'ieee-p1363' },
    Buffer.from(signature, 'base64url')), true);
  return JSON.parse(Buffer.from(payload, 'base64url'));
}

function authorizationDetails(request) {
  return [{ type: 'atum', permissions: request.permissions, grant_limit: request.grant_limit,
    grant_expires_at_ms: request.grant_expires_at_ms }];
}

function token(request, refreshToken) {
  return { access_token: ACCESS, expires_in: 60, refresh_token: refreshToken, scope: 'atum:invoke', token_type: 'DPoP',
    authorization_details: authorizationDetails(request) };
}

function configuration(origin, ca) {
  const registration = structuredClone(vector.registry.registration);
  registration.issuer = origin;
  return {
    registration,
    client: structuredClone(vector.registry.clients[0]),
    endpoints: {
      options_url: `${origin}/atum/request/options`, verify_url: `${origin}/atum/request/verify`,
      par_url: `${origin}/request`, authorization_url: `${origin}/auth`,
      device_authorization_url: `${origin}/device/auth`, token_url: `${origin}/token`,
    },
    issuerCaPem: ca,
    clock: () => ({ now_ms: NOW, uncertainty_ms: 0, healthy: true }),
  };
}

export function signingPorts() {
  const sign = async input => nodeSign('sha256', input, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return {
    hardwareKey: Object.freeze({ signEs256: sign }),
    signingPort: Object.freeze({ signEs256IeeeP1363: sign }),
  };
}

export function requestInput() {
  const detail = vector.input.authorization_details[0];
  return {
    permissions: structuredClone(detail.permissions),
    grant_limit: detail.grant_limit,
    grant_expires_at_ms: NOW + 299_877,
    redirect_uri: vector.input.code.redirect_uri,
  };
}

export async function startDocumentationFixture() {
  const certs = certificates();
  let origin;
  let prepared;
  let parState;
  let tokenCalls = 0;
  const routeCalls = [];
  const server = https.createServer({ cert: certs.cert, key: certs.key }, async (request, response) => {
    const raw = await body(request);
    routeCalls.push(request.url);
    if (request.url === '/atum/request/options') {
      const options = JSON.parse(raw);
      const detail = options.authorization_details[0];
      const registration = configuration(origin, certs.ca).registration;
      const normalizedRegistration = { ...registration,
        account_required_actions: [...registration.account_required_actions].sort() };
      const requestRecord = {
        profile: 'atum-oauth-request-v1', request_id: REQUEST_ID, created_at_ms: NOW,
        expires_at_ms: Math.floor(Math.min(NOW + 300_000, detail.grant_expires_at_ms) / 1000) * 1000,
        issuer: origin, environment: 'sandbox', flow: options.flow, client_id: options.client_id,
        registration: normalizedRegistration, resource: registration.audience, scope: 'atum:invoke',
        permissions: detail.permissions, grant_limit: detail.grant_limit,
        grant_expires_at_ms: detail.grant_expires_at_ms, code: options.code,
      };
      prepared = {
        request: requestRecord, request_hash: digest('atum.oauth.request.v1\n', requestRecord),
        challenge_id: CHALLENGE_ID, nonce: REQUEST_NONCE,
        iat: Math.floor(requestRecord.created_at_ms / 1000), exp: requestRecord.expires_at_ms / 1000,
      };
      return json(response, 200, prepared);
    }
    if (request.url === '/atum/request/verify') {
      assert.ok(prepared);
      return json(response, 200, {
        atum_request: HANDLE, request_id: prepared.request.request_id, request_hash: prepared.request_hash,
        agent_key_thumbprint: vector.expected.agent_key_thumbprint, state: 'verified',
        expires_at_ms: prepared.request.expires_at_ms,
      });
    }
    if (request.url === '/request') {
      assert.ok(prepared);
      const form = new URLSearchParams(raw.toString('utf8'));
      parState = form.get('state');
      assert.equal(form.get('atum_request'), HANDLE);
      assert.equal(decodeProof(request.headers.dpop).htu, `${origin}/request`);
      return json(response, 201, {
        request_uri: `urn:ietf:params:oauth:request_uri:${'P'.repeat(43)}`, expires_in: 60,
      });
    }
    if (request.url === '/device/auth') {
      assert.ok(prepared);
      assert.equal(decodeProof(request.headers.dpop).htu, `${origin}/device/auth`);
      return json(response, 200, {
        device_code: 'D'.repeat(43), user_code: 'BCDF-GHJK', verification_uri: `${origin}/device`,
        verification_uri_complete: `${origin}/device?user_code=BCDF-GHJK`, expires_in: 120, interval: 1,
      });
    }
    assert.equal(request.url, '/token');
    assert.ok(prepared);
    tokenCalls += 1;
    const proof = decodeProof(request.headers.dpop);
    assert.equal(proof.htu, `${origin}/token`);
    if (tokenCalls % 2 === 1) {
      assert.equal(proof.nonce, undefined);
      return json(response, 400, { error: 'use_dpop_nonce' }, { 'dpop-nonce': DPOP_NONCE });
    }
    assert.equal(proof.nonce, DPOP_NONCE);
    return json(response, 200, token(prepared.request, tokenCalls === 2 ? FIRST_REFRESH : SECOND_REFRESH));
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  origin = `https://localhost:${server.address().port}`;
  const values = configuration(origin, certs.ca);
  return {
    ...values,
    callbackUrl() {
      assert.ok(parState);
      return `${vector.input.code.redirect_uri}?code=${CODE}&state=${encodeURIComponent(parState)}&iss=${encodeURIComponent(origin)}`;
    },
    state: () => ({ routeCalls: [...routeCalls], tokenCalls }),
    close: async () => {
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
      rmSync(certs.directory, { recursive: true, force: true });
    },
  };
}

export function resourceExample(key) {
  const actionRequest = { action: 'order.preview',
    parameters: { resource: 'ENERGY', amount: 2, duration: 30, max_price_sun: 9 } };
  const registration = {
    issuer: 'https://issuer.example.test', audience: 'atum-api', environment: 'sandbox', tenant_id: 'tenant',
    resource_id: 'resource', quota_scope_id: 'quota', operation_namespace: 'orders',
    resource_profile_version: 'v1-draft.1',
    resource_profile_hash: 'sha256:dc6f6409a47da2a97ea7b4ace313985d7fcd4c6b8459a59ea06b014de304a175',
    policy_version: 'policy', account_required_actions: ['order.preview'],
  };
  const context = {
    protocol_version: '0.1.0-draft.2', resource_profile_version: registration.resource_profile_version,
    resource_profile_hash: registration.resource_profile_hash, issuer: registration.issuer, audience: registration.audience,
    environment: registration.environment, tenant_id: registration.tenant_id, resource_id: registration.resource_id,
    quota_scope_id: registration.quota_scope_id, operation_namespace: registration.operation_namespace,
    scoped_subject: 'subject', operation_id: 'operation', grant_id: 'grant', grant_version: 1,
    consent_hash: `sha256:${'a'.repeat(64)}`, account_binding_id: 'account', account_binding_version: 1,
    action: actionRequest.action, action_hash: actionHash(actionRequest), policy_version: registration.policy_version,
    agent_key_thumbprint: key.thumbprint,
  };
  return {
    registration, endpoint: { method: 'POST', url: 'https://resource.example.test/v1/orders' },
    clock: () => ({ now_ms: 1_800_000_000_000, uncertainty_ms: 0, healthy: true }),
    accessToken: 'not-a-jwt.still-opaque.signature', context, actionRequest,
    nonce: Buffer.alloc(32, 7).toString('base64url'),
  };
}
