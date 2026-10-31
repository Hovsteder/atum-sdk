import type { AgentClient, AgentConfig } from './common.js';

export function createAgentClient(config: AgentConfig): Promise<AgentClient>;

export type {
  AgentClient, AgentConfig, AgentTokenResult, AuthorizationCodeFlow, AuthorizationCodeRequest, AuthorizationDetail,
  DeviceAuthorizationFlow, DeviceAuthorizationRequest, DevicePollInput, RefreshInput,
} from './common.js';
