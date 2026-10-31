export type AgentErrorCode =
  | 'invalid_request'
  | 'invalid_proof'
  | 'access_denied'
  | 'invalid_grant'
  | 'expired_token'
  | 'temporarily_unavailable';

export type AgentAction = 'prices.read' | 'order.preview' | 'sandbox.execute';
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

export interface AgentRegistration {
  readonly issuer: string;
  readonly audience: string;
  readonly environment: 'sandbox';
  readonly tenant_id: string;
  readonly resource_id: string;
  readonly quota_scope_id: string;
  readonly operation_namespace: string;
  readonly resource_profile_version: 'v1-draft.1';
  readonly resource_profile_hash: 'sha256:dc6f6409a47da2a97ea7b4ace313985d7fcd4c6b8459a59ea06b014de304a175';
  readonly policy_version: string;
  readonly account_required_actions: ReadonlyArray<AgentAction>;
}

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
  readonly ca: string;
}

export interface AgentConfig {
  readonly registration: AgentRegistration;
  readonly client: RegisteredAgentClient;
  readonly endpoints: AgentEndpoints;
  readonly tls: AgentTlsConfig;
  readonly key: AgentKey;
  readonly clock: AgentClock;
  readonly timeoutMs?: number;
  readonly maxConcurrent?: number;
}

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

/**
 * Action-specific public permission shapes. Runtime checks still enforce
 * closed objects and numeric ranges for values received from callers.
 */
export type AgentPermission = PricesReadPermission | BoundedAgentPermission;

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

export interface PreparedRequestRecord {
  readonly profile: 'atum-oauth-request-v1';
  readonly request_id: string;
  readonly created_at_ms: number;
  readonly expires_at_ms: number;
  readonly issuer: string;
  readonly environment: 'sandbox';
  readonly flow: AgentFlow;
  readonly client_id: string;
  readonly registration: AgentRegistration;
  readonly resource: string;
  readonly scope: 'atum:invoke';
  readonly permissions: ReadonlyArray<AgentPermission>;
  readonly grant_limit: number;
  readonly grant_expires_at_ms: number;
  readonly code: PreparedCodeMetadata | null;
}

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

export interface ResourceContext {
  readonly protocol_version: '0.1.0-draft.2';
  readonly resource_profile_version: 'v1-draft.1';
  readonly resource_profile_hash: 'sha256:dc6f6409a47da2a97ea7b4ace313985d7fcd4c6b8459a59ea06b014de304a175';
  readonly issuer: string;
  readonly audience: string;
  readonly environment: 'sandbox';
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
  readonly action: AgentAction;
}

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

export type ResourceActionRequest = PricesReadActionRequest | BoundedResourceActionRequest;

export interface ProtectedRequestSignerConfig {
  readonly key: AgentKey;
  readonly registration: AgentRegistration;
  readonly endpoint: ProtectedResourceEndpoint;
  readonly clock: AgentClock;
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
