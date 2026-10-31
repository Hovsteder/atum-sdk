export type AgentErrorCode =
  | 'invalid_request'
  | 'invalid_proof'
  | 'access_denied'
  | 'invalid_grant'
  | 'expired_token'
  | 'temporarily_unavailable';

export type LegacyAgentAction = 'prices.read' | 'order.preview' | 'sandbox.execute' | 'energy.purchase';
export type ServiceActionName = string;
export type AgentAction = LegacyAgentAction | ServiceActionName;
export type AgentFlow = 'authorization_code' | 'device_code';

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonArray;
export interface JsonObject {
  readonly [key: string]: JsonValue;
}
export interface JsonArray extends ReadonlyArray<JsonValue> {}

export interface P256PublicJwk {
  readonly kty: 'EC';
  readonly crv: 'P-256';
  readonly x: string;
  readonly y: string;
}

export interface AgentKeySignOptions {
  readonly timeoutMs: number;
}

export interface AgentKey {
  readonly publicJwk: P256PublicJwk;
  readonly thumbprint: string;
  sign(input: Uint8Array, options?: AgentKeySignOptions): Promise<Uint8Array>;
}

export interface AgentKeyPort {
  readonly publicJwk: P256PublicJwk;
  readonly sign: (input: Uint8Array) => Promise<Uint8Array> | Uint8Array;
  readonly timeoutMs?: number;
}

export interface WebCryptoAgentKeyOptions {
  readonly publicJwk: P256PublicJwk;
  readonly privateKey: CryptoKey;
  readonly timeoutMs?: number;
}

export interface AgentClockReading {
  readonly now_ms: number;
  readonly uncertainty_ms: number;
  readonly healthy: boolean;
}

export type AgentClock = () => AgentClockReading;

export interface AgentRegistrationFields {
  readonly issuer: string;
  readonly audience: string;
  readonly tenant_id: string;
  readonly resource_id: string;
  readonly quota_scope_id: string;
  readonly operation_namespace: string;
  readonly policy_version: string;
}

export interface SandboxAgentRegistration extends AgentRegistrationFields {
  readonly environment: 'sandbox';
  readonly resource_profile_version: 'v1-draft.1';
  readonly resource_profile_hash: 'sha256:dc6f6409a47da2a97ea7b4ace313985d7fcd4c6b8459a59ea06b014de304a175';
  readonly account_required_actions: ReadonlyArray<'prices.read' | 'order.preview' | 'sandbox.execute'>;
}

export interface EnergyAgentRegistration extends AgentRegistrationFields {
  readonly environment: 'production';
  readonly resource_profile_version: 'merx.energy-purchase.v1-draft.1';
  readonly resource_profile_hash: 'sha256:e1c5106dc710ce0ba3d846f3cb376358eb858c35adfbac906f0ff58f3a6451fa';
  readonly account_required_actions: ReadonlyArray<'prices.read' | 'order.preview' | 'energy.purchase'>;
}

export interface ServiceActionDescriptor {
  readonly profile: 'atum.service-actions.v1-draft.1';
  readonly actions: ReadonlyArray<ServiceActionName>;
  readonly account_required_actions: ReadonlyArray<ServiceActionName>;
}

export interface GenericAgentRegistration extends AgentRegistrationFields {
  readonly environment: 'sandbox' | 'production';
  readonly resource_profile_version: 'atum.service-actions.v1-draft.1';
  readonly resource_profile_hash: `sha256:${string}`;
  readonly account_required_actions: ReadonlyArray<ServiceActionName>;
}

export type LegacyAgentRegistration = SandboxAgentRegistration | EnergyAgentRegistration;
export type AgentRegistration = LegacyAgentRegistration | GenericAgentRegistration;

export interface RegisteredAgentClient {
  readonly client_id: string;
  readonly flows: ReadonlyArray<AgentFlow>;
  readonly redirect_uris: ReadonlyArray<string>;
  readonly permissions: ReadonlyArray<AgentAction>;
  readonly max_grant_limit: number;
  readonly max_grant_lifetime_ms: number;
}

export interface AgentEndpoints {
  readonly options_url: string;
  readonly verify_url: string;
  readonly par_url: string;
  readonly authorization_url: string;
  readonly device_authorization_url: string;
  readonly token_url: string;
}

export interface AgentTlsConfig {
  readonly ca?: string;
}

export interface AgentConfigFields {
  readonly client: RegisteredAgentClient;
  readonly endpoints: AgentEndpoints;
  readonly tls: AgentTlsConfig;
  readonly key: AgentKey;
  readonly clock: AgentClock;
  readonly timeoutMs?: number;
  readonly maxConcurrent?: number;
}

export interface LegacyAgentConfig extends AgentConfigFields {
  readonly registration: LegacyAgentRegistration;
  readonly descriptor?: never;
}

export interface GenericAgentConfig extends AgentConfigFields {
  readonly registration: GenericAgentRegistration;
  readonly descriptor: ServiceActionDescriptor;
}

export type AgentConfig = LegacyAgentConfig | GenericAgentConfig;

/** The one field accepted for the read-only permission wire object. */
export interface PricesReadPermission {
  readonly action: 'prices.read';
}

/** Limits required by the two bounded permission wire objects. */
export interface BoundedAgentPermission {
  readonly action: 'order.preview' | 'sandbox.execute';
  readonly max_amount: number;
  readonly max_duration: number;
  readonly max_price_sun: number | null;
}

export type OrderPreviewPermission = BoundedAgentPermission & {
  readonly action: 'order.preview';
};

export type SandboxExecutePermission = BoundedAgentPermission & {
  readonly action: 'sandbox.execute';
};

export interface EnergyPurchaseParameters {
  readonly network: 'tron-mainnet';
  readonly resource: 'ENERGY';
  readonly amount: number;
  readonly duration_sec: 120 | 300 | 600 | 900 | 1800 | 3600 | 10800 | 21600 | 86400;
  readonly recipient: string;
  readonly execution_provider: 'powersun-merx';
  readonly quote_id: string;
  readonly quote_expires_at_ms: number;
  readonly resource_cost_sun: string;
  readonly platform_fee_sun: '0';
  readonly activation_fee_cap_sun: string;
  readonly network_fee_cap_sun: '0';
  readonly max_total_debit_sun: string;
}

export interface EnergyPurchasePermission {
  readonly action: 'energy.purchase';
  readonly parameters: EnergyPurchaseParameters;
}

/** Neutral service permissions name one descriptor-registered action and carry no constraints. */
export interface NamedServicePermission {
  readonly action: ServiceActionName;
}

/**
 * Action-specific public permission shapes. Runtime checks still enforce
 * closed objects and numeric ranges for values received from callers.
 */
export type AgentPermission = PricesReadPermission | BoundedAgentPermission | EnergyPurchasePermission | NamedServicePermission;

export interface AuthorizationCodeRequest {
  readonly permissions: ReadonlyArray<AgentPermission>;
  readonly grant_limit: number;
  readonly grant_expires_at_ms: number;
  readonly redirect_uri: string;
}

export interface DeviceAuthorizationRequest {
  readonly permissions: ReadonlyArray<AgentPermission>;
  readonly grant_limit: number;
  readonly grant_expires_at_ms: number;
}

export interface RequestProofAuthorizationCodeInput extends AuthorizationCodeRequest {
  readonly flow: 'authorization_code';
  readonly code_challenge: string;
  readonly state: string;
}

export interface RequestProofDeviceInput extends DeviceAuthorizationRequest {
  readonly flow: 'device_code';
}

export type RequestProofInput = RequestProofAuthorizationCodeInput | RequestProofDeviceInput;

export interface PreparedCodeMetadata {
  readonly redirect_uri: string;
  readonly code_challenge: string;
  readonly code_challenge_method: 'S256';
  readonly state: string;
}

export interface PreparedRequestRecordFields {
  readonly profile: 'atum-oauth-request-v1';
  readonly request_id: string;
  readonly created_at_ms: number;
  readonly expires_at_ms: number;
  readonly issuer: string;
  readonly flow: AgentFlow;
  readonly client_id: string;
  readonly resource: string;
  readonly scope: 'atum:invoke';
  readonly permissions: ReadonlyArray<AgentPermission>;
  readonly grant_limit: number;
  readonly grant_expires_at_ms: number;
  readonly code: PreparedCodeMetadata | null;
}

export interface SandboxPreparedRequestRecord extends PreparedRequestRecordFields {
  readonly environment: 'sandbox';
  readonly registration: SandboxAgentRegistration;
}

export interface EnergyPreparedRequestRecord extends PreparedRequestRecordFields {
  readonly environment: 'production';
  readonly registration: EnergyAgentRegistration;
}

export interface GenericPreparedRequestRecord extends PreparedRequestRecordFields {
  readonly environment: 'sandbox' | 'production';
  readonly registration: GenericAgentRegistration;
}

export type PreparedRequestRecord = SandboxPreparedRequestRecord | EnergyPreparedRequestRecord | GenericPreparedRequestRecord;

export interface PreparedOwnerRequest {
  readonly request: PreparedRequestRecord;
  readonly request_hash: string;
  readonly atum_request: string;
  readonly expires_at_ms: number;
}

export interface AuthorizationDetail {
  readonly type: 'atum';
  readonly permissions: ReadonlyArray<AgentPermission>;
  readonly grant_limit: number;
  readonly grant_expires_at_ms: number;
}

export interface AgentTokenResult {
  readonly access_token: string;
  readonly expires_in: number;
  readonly refresh_token: string;
  readonly scope: 'atum:invoke';
  readonly token_type: 'DPoP';
  readonly authorization_details: readonly [AuthorizationDetail];
}

export interface RefreshInput {
  readonly refresh_token: string;
  readonly authorization_details: readonly [AuthorizationDetail];
}

export interface AuthorizationCodeFlow {
  readonly authorization_url: string;
  readonly request_id: string;
  readonly expires_at_ms: number;
  completeCallback(callback: string): Promise<AgentTokenResult>;
}

export interface DevicePollInput {
  readonly signal: AbortSignal;
}

export interface DeviceAuthorizationFlow {
  readonly verification_uri: string;
  readonly verification_uri_complete: string;
  readonly user_code: string;
  readonly request_id: string;
  readonly expires_at_ms: number;
  readonly interval_ms: number;
  poll(input: DevicePollInput): Promise<AgentTokenResult>;
}

export interface AgentClient {
  beginAuthorizationCode(input: AuthorizationCodeRequest): Promise<AuthorizationCodeFlow>;
  beginDeviceAuthorization(input: DeviceAuthorizationRequest): Promise<DeviceAuthorizationFlow>;
  refresh(input: RefreshInput): Promise<AgentTokenResult>;
  close(): Promise<void>;
}

export interface ProtectedResourceEndpoint {
  readonly method: 'POST';
  readonly url: string;
}

export interface ResourceContextFields {
  readonly protocol_version: '0.1.0-draft.2';
  readonly issuer: string;
  readonly audience: string;
  readonly tenant_id: string;
  readonly resource_id: string;
  readonly quota_scope_id: string;
  readonly operation_namespace: string;
  readonly scoped_subject: string;
  readonly operation_id: string;
  readonly grant_id: string;
  readonly grant_version: number;
  readonly policy_version: string;
  readonly agent_key_thumbprint: string;
  readonly consent_hash: string;
  readonly action_hash: string;
  readonly account_binding_id: string | null;
  readonly account_binding_version: number | null;
}

export interface SandboxResourceContext extends ResourceContextFields {
  readonly resource_profile_version: 'v1-draft.1';
  readonly resource_profile_hash: 'sha256:dc6f6409a47da2a97ea7b4ace313985d7fcd4c6b8459a59ea06b014de304a175';
  readonly environment: 'sandbox';
  readonly action: 'prices.read' | 'order.preview' | 'sandbox.execute';
}

export interface EnergyResourceContext extends ResourceContextFields {
  readonly resource_profile_version: 'merx.energy-purchase.v1-draft.1';
  readonly resource_profile_hash: 'sha256:e1c5106dc710ce0ba3d846f3cb376358eb858c35adfbac906f0ff58f3a6451fa';
  readonly environment: 'production';
  readonly action: 'prices.read' | 'order.preview' | 'energy.purchase';
}

export interface GenericResourceContext extends ResourceContextFields {
  readonly resource_profile_version: 'atum.service-actions.v1-draft.1';
  readonly resource_profile_hash: `sha256:${string}`;
  readonly environment: 'sandbox' | 'production';
  readonly action: ServiceActionName;
}

export type ResourceContext = SandboxResourceContext | EnergyResourceContext | GenericResourceContext;

export interface PricesReadActionRequest {
  readonly action: 'prices.read';
  readonly parameters: Readonly<Record<string, never>>;
}

export interface BoundedResourceActionRequest {
  readonly action: 'order.preview' | 'sandbox.execute';
  readonly parameters: Readonly<{
    resource: 'ENERGY' | 'BANDWIDTH';
    amount: number;
    duration: number;
    max_price_sun?: number;
  }>;
}

export interface EnergyPurchaseActionRequest extends EnergyPurchasePermission {}

export interface GenericServiceActionRequest {
  readonly action: ServiceActionName;
  readonly parameters: JsonObject;
}

export type ResourceActionRequest = PricesReadActionRequest | BoundedResourceActionRequest | EnergyPurchaseActionRequest | GenericServiceActionRequest;

export interface ProtectedRequestSignerConfig {
  readonly key: AgentKey;
  readonly registration: AgentRegistration;
  readonly endpoint: ProtectedResourceEndpoint;
  readonly clock: AgentClock;
  readonly descriptor?: ServiceActionDescriptor;
  readonly timeoutMs?: number;
}

export interface ProtectedRequestChallengeInput {
  readonly access_token: string;
  readonly context: ResourceContext;
  readonly action_request: ResourceActionRequest;
}

export interface ProtectedRequestInput extends ProtectedRequestChallengeInput {
  readonly nonce: string;
}

export interface SignatureArtifact {
  readonly authorization: string;
  readonly dpop: string;
  readonly body: string;
  readonly method: 'POST';
  readonly url: string;
}

export interface ProtectedRequestSigner {
  signChallenge(input: ProtectedRequestChallengeInput): Promise<SignatureArtifact>;
  sign(input: ProtectedRequestInput): Promise<SignatureArtifact>;
}
