import type { AgentConfig, PreparedOwnerRequest, RequestProofInput } from './common.js';

export interface RequestProofClient {
  prepare(input: RequestProofInput): Promise<PreparedOwnerRequest>;
  close(): Promise<void>;
}

export function createRequestProofClient(config: AgentConfig): RequestProofClient;

export type {
  AgentAction, AgentClock, AgentClockReading, AgentConfig, AgentEndpoints, AgentPermission, AgentRegistration,
  AgentTlsConfig, AuthorizationDetail, DeviceAuthorizationRequest, PreparedCodeMetadata, PreparedOwnerRequest,
  PreparedRequestRecord, PricesReadPermission, BoundedAgentPermission, OrderPreviewPermission, SandboxExecutePermission,
  RegisteredAgentClient, RequestProofAuthorizationCodeInput, RequestProofDeviceInput,
  RequestProofInput,
} from './common.js';
