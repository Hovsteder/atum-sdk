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
  type EnergyAgentRegistration,
  type EnergyPurchaseActionRequest,
  type EnergyPurchasePermission,
  type EnergyPurchaseResult,
  type EnergyResourceContext,
  type GenericAgentConfig,
  type GenericResourceContext,
  type GenericServiceActionRequest,
  type NamedServicePermission,
  type ServiceActionDescriptor,
  type ResourceActionRequest,
  type ResourceContext,
} from '@atum/agent';
import {
  createCurrentAuthorizationVerifier,
  type CurrentAuthorizationConfig,
  type CurrentAuthorizationResult,
} from '@atum/verification/current-authorization';

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
const energyPermission: EnergyPurchasePermission = { action: 'energy.purchase', parameters: {
  network: 'tron-mainnet', resource: 'ENERGY', amount: 65000, duration_sec: 3600,
  recipient: 'TA4Wt1DUCqz6YegbnsmqsWC5uUfbdBqPxm', execution_provider: 'powersun-merx',
  quote_id: '123e4567-e89b-42d3-a456-426614174000', quote_expires_at_ms: 1800000000000,
  resource_cost_sun: '1105000', platform_fee_sun: '0', activation_fee_cap_sun: '100000',
  network_fee_cap_sun: '0', max_total_debit_sun: '1205000'
} };
void readPermission;
void boundedPermission;
void orderPreviewPermission;
void sandboxPermission;
void energyPermission;

const energyRegistration: EnergyAgentRegistration = {
  issuer: 'https://issuer.example.test', audience: 'https://merx.example.test', environment: 'production',
  tenant_id: 'merx', resource_id: 'energy', quota_scope_id: 'account', operation_namespace: 'energy',
  resource_profile_version: 'merx.energy-purchase.v1-draft.1',
  resource_profile_hash: 'sha256:e1c5106dc710ce0ba3d846f3cb376358eb858c35adfbac906f0ff58f3a6451fa',
  policy_version: 'owner-passkey-v1', account_required_actions: ['energy.purchase'],
};
const energyConfig: AgentConfig = {
  registration: energyRegistration,
  client: { client_id: 'energy-agent', flows: ['device_code'], redirect_uris: ['https://agent.example.test/callback'],
    permissions: ['energy.purchase'], max_grant_limit: 1, max_grant_lifetime_ms: 600_000 },
  endpoints: { options_url: 'https://issuer.example.test/atum/request/options', verify_url: 'https://issuer.example.test/atum/request/verify',
    par_url: 'https://issuer.example.test/request', authorization_url: 'https://issuer.example.test/auth',
    device_authorization_url: 'https://issuer.example.test/device/auth', token_url: 'https://issuer.example.test/token' },
  tls: { ca: 'test-ca' }, key, clock: dynamicHealthClock,
};
const energyAction: EnergyPurchaseActionRequest = energyPermission;
const energyContext: EnergyResourceContext = {
  protocol_version: '0.1.0-draft.2', resource_profile_version: energyRegistration.resource_profile_version,
  resource_profile_hash: energyRegistration.resource_profile_hash, issuer: energyRegistration.issuer,
  audience: energyRegistration.audience, environment: 'production', tenant_id: 'merx', resource_id: 'energy',
  quota_scope_id: 'account', operation_namespace: 'energy', scoped_subject: 'owner-1', operation_id: 'operation-1',
  grant_id: 'grant-1', grant_version: 1, policy_version: 'owner-passkey-v1', agent_key_thumbprint: 'thumbprint',
  consent_hash: 'sha256:consent', action_hash: 'sha256:action', account_binding_id: 'binding-1',
  account_binding_version: 1, action: 'energy.purchase',
};

async function energyClientCalls(): Promise<void> {
  const energyAgent = await createAgentClient(energyConfig);
  const resource = createProtectedResourceClient({ key, registration: energyRegistration,
    endpoint: { method: 'POST', url: 'https://merx.example.test/v1/atum/operations' }, clock: dynamicHealthClock });
  const invocation = await resource.invoke({ access_token: 'token', context: energyContext, action_request: energyAction });
  const delivered: EnergyPurchaseResult = { order_id: '123e4567-e89b-42d3-a456-426614174000',
    status: 'delivered', charged_sun: '1105000' };
  void invocation;
  void delivered;
  await resource.close();
  await energyAgent.close();
}

// @ts-expect-error Energy delivery status is a closed literal.
const invalidEnergyResult: EnergyPurchaseResult = { order_id: '123e4567-e89b-42d3-a456-426614174000', status: 'pending', charged_sun: '1105000' };
void invalidEnergyResult;

declare const currentAuthorizationConfig: CurrentAuthorizationConfig;
declare const protectedRequest: { authorization: string; dpop: string; body: string; method: string; url: string };
async function currentAuthorizationCalls(): Promise<void> {
  const verifier = await createCurrentAuthorizationVerifier(currentAuthorizationConfig);
  const current: CurrentAuthorizationResult = await verifier.verifyCurrent(protectedRequest);
  const originalLimit: number = current.grant_limit;
  const acceptanceRequired: true = current.requires_resource_acceptance;
  void originalLimit; void acceptanceRequired;
  await verifier.close();
}
void currentAuthorizationCalls;

// @ts-expect-error a fresh authority transport is required by the public composition.
void createCurrentAuthorizationVerifier({ registration: {}, proof: {}, clock: dynamicHealthClock });

// @ts-expect-error the action property is required before runtime validation.
const missingAction: AgentPermission = {};
void missingAction;

// @ts-expect-error prices.read has no bound fields in its closed wire object.
const extraPricesReadBound: AgentPermission = { action: 'prices.read', max_amount: 1 };
void extraPricesReadBound;

const serviceDescriptor: ServiceActionDescriptor = {
  profile: 'atum.service-actions.v1-draft.1',
  actions: ['calendar.event.read', 'document.read', 'storage.object.write'],
  account_required_actions: ['storage.object.write'],
};
const serviceRegistration = {
  issuer: 'https://issuer.example.test', audience: 'https://calendar.example.test', environment: 'sandbox' as const,
  tenant_id: 'calendar', resource_id: 'calendar-api', quota_scope_id: 'owner', operation_namespace: 'calendar-operations',
  resource_profile_version: 'atum.service-actions.v1-draft.1' as const,
  resource_profile_hash: 'sha256:6c4f1bbc3b6ed1b3863049bb467868bbd13c58edf734e4a6bcd48b15002fce8b' as const,
  policy_version: 'owner-passkey-v1', account_required_actions: ['storage.object.write'],
};
const serviceConfig: GenericAgentConfig = {
  registration: serviceRegistration, descriptor: serviceDescriptor,
  client: { client_id: 'calendar-agent', flows: ['authorization_code'], redirect_uris: ['https://agent.example.test/callback'],
    permissions: ['calendar.event.read'], max_grant_limit: 2, max_grant_lifetime_ms: 600_000 },
  endpoints: energyConfig.endpoints, tls: {}, key, clock: dynamicHealthClock,
};
const namedPermission: NamedServicePermission = { action: 'calendar.event.read' };
const serviceAction: GenericServiceActionRequest = { action: 'calendar.event.read', parameters: { calendar_id: 'primary' } };
const serviceContext: GenericResourceContext = {
  ...energyContext, resource_profile_version: 'atum.service-actions.v1-draft.1',
  resource_profile_hash: serviceRegistration.resource_profile_hash, environment: 'sandbox',
  issuer: serviceRegistration.issuer, audience: serviceRegistration.audience, tenant_id: 'calendar',
  resource_id: 'calendar-api', quota_scope_id: 'owner', operation_namespace: 'calendar-operations',
  account_binding_id: null, account_binding_version: null, action: 'calendar.event.read',
};

async function genericServiceCalls(): Promise<void> {
  const agent = await createAgentClient(serviceConfig);
  await agent.beginAuthorizationCode({ permissions: [namedPermission], grant_limit: 2,
    grant_expires_at_ms: 1_800_000_000_000, redirect_uri: 'https://agent.example.test/callback' });
  const signer = createProtectedRequestSigner({ key, registration: serviceRegistration, descriptor: serviceDescriptor,
    endpoint: { method: 'POST', url: 'https://calendar.example.test/v1/atum/operations' }, clock: dynamicHealthClock });
  await signer.signChallenge({ access_token: 'token', context: serviceContext, action_request: serviceAction });
  await agent.close();
}

// @ts-expect-error a neutral registration requires its trusted descriptor beside it.
const missingServiceDescriptor: GenericAgentConfig = { ...serviceConfig, descriptor: undefined };
void missingServiceDescriptor;

// @ts-expect-error neutral permissions cannot carry unregistered restriction fields.
const invalidNamedPermission: NamedServicePermission = { action: 'calendar.event.read', restriction: {} };
void invalidNamedPermission;

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
void energyClientCalls;
void genericServiceCalls;
void rejectedCalls;
void handlesSafeError;
