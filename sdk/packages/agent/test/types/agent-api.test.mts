import {
  AgentError,
  createAgentClient,
  createAgentKey,
  createProtectedResourceClient,
  createProtectedRequestSigner,
  createRequestProofClient,
  type AgentConfig,
  type AgentClock,
  type AgentKey,
  type AgentPermission,
  type BoundedAgentPermission,
  type OrderPreviewPermission,
  type PricesReadPermission,
  type SandboxExecutePermission,
  type ResourceActionRequest,
  type ResourceContext,
} from '@atum/agent';

declare const config: AgentConfig;
declare const key: AgentKey;
declare const context: ResourceContext;
declare const actionRequest: ResourceActionRequest;

const dynamicHealthClock: AgentClock = () => ({
  now_ms: Date.now(),
  uncertainty_ms: 1,
  healthy: Math.random() > 0.5,
});
void dynamicHealthClock;

async function documentedCalls(): Promise<void> {
  const signedKey = await createAgentKey({
    publicJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
    sign: async input => new Uint8Array(input),
    timeoutMs: 3_000,
  });
  const requests = createRequestProofClient(config);
  const prepared = await requests.prepare({
    flow: 'authorization_code',
    permissions: [{ action: 'prices.read' }],
    grant_limit: 1,
    grant_expires_at_ms: 1_800_000_000_000,
    redirect_uri: 'https://agent.example.test/callback',
    code_challenge: 'challenge',
    state: 'state',
  });
  const agent = await createAgentClient(config);
  const code = await agent.beginAuthorizationCode({
    permissions: [{ action: 'prices.read' }],
    grant_limit: 1,
    grant_expires_at_ms: 1_800_000_000_000,
    redirect_uri: 'https://agent.example.test/callback',
  });
  const tokens = await code.completeCallback('https://agent.example.test/callback?code=code&state=state&iss=https%3A%2F%2Fissuer.example.test');
  await agent.refresh({ refresh_token: tokens.refresh_token, authorization_details: tokens.authorization_details });
  const signer = createProtectedRequestSigner({
    key,
    registration: config.registration,
    endpoint: { method: 'POST', url: 'https://resource.example.test/v1/orders' },
    clock: config.clock,
  });
  await signer.signChallenge({ access_token: tokens.access_token, context, action_request: actionRequest });
  const resource = createProtectedResourceClient({ key, registration: config.registration,
    endpoint: { method: 'POST', url: 'https://resource.example.test/v1/atum/operations' }, clock: config.clock });
  await resource.close();
  await agent.close();
  await requests.close();
  void prepared.request.request_id;
  void signedKey.thumbprint;
}

const acceptedPermission: AgentPermission = { action: 'order.preview', max_amount: 1, max_duration: 1, max_price_sun: null };
void acceptedPermission;

const readPermission: PricesReadPermission = { action: 'prices.read' };
const boundedPermission: BoundedAgentPermission = { action: 'sandbox.execute', max_amount: 1, max_duration: 1, max_price_sun: null };
const orderPreviewPermission: OrderPreviewPermission = { action: 'order.preview', max_amount: 1, max_duration: 1, max_price_sun: null };
const sandboxPermission: SandboxExecutePermission = { action: 'sandbox.execute', max_amount: 1, max_duration: 1, max_price_sun: null };
void readPermission;
void boundedPermission;
void orderPreviewPermission;
void sandboxPermission;

// @ts-expect-error unsupported permissions are rejected by the public type.
const unsupportedPermission: AgentPermission = { action: 'orders.write' };
void unsupportedPermission;

// @ts-expect-error the action property is required before runtime validation.
const missingAction: AgentPermission = {};
void missingAction;

// @ts-expect-error bounded permissions require all three action limits.
const missingPermissionBounds: AgentPermission = { action: 'order.preview' };
void missingPermissionBounds;

// @ts-expect-error prices.read has no bound fields in its closed wire object.
const extraPricesReadBound: AgentPermission = { action: 'prices.read', max_amount: 1 };
void extraPricesReadBound;

async function rejectedCalls(): Promise<void> {
  const agent = await createAgentClient(config);
  // @ts-expect-error the public client has no execution API.
  await agent.execute();
  const signer = createProtectedRequestSigner({
    key,
    registration: config.registration,
    endpoint: { method: 'POST', url: 'https://resource.example.test/v1/orders' },
    clock: config.clock,
  });
  // @ts-expect-error context is required for protected signing.
  await signer.signChallenge({ access_token: 'opaque', action_request: actionRequest });
  await agent.close();
}

function handlesSafeError(error: Error): void {
  if (error instanceof AgentError) {
    const code: 'invalid_request' | 'invalid_proof' | 'access_denied' | 'invalid_grant' | 'expired_token' | 'temporarily_unavailable' = error.code;
    void code;
  }
}

void documentedCalls;
void rejectedCalls;
void handlesSafeError;
