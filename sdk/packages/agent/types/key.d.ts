import type { AgentErrorCode, AgentKey, AgentKeyPort, WebCryptoAgentKeyOptions } from './common.js';

export class AgentError extends Error {
  constructor(code: AgentErrorCode);
  readonly code: AgentErrorCode;
}

export function createAgentKey(value: AgentKeyPort): Promise<AgentKey>;
export function createWebCryptoAgentKey(value: WebCryptoAgentKeyOptions): Promise<AgentKey>;

export type { AgentErrorCode, AgentKey, AgentKeyPort, AgentKeySignOptions, P256PublicJwk, WebCryptoAgentKeyOptions } from './common.js';
