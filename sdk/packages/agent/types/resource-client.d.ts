import type { AgentClock, AgentKey, AgentRegistration, JsonValue, ProtectedRequestChallengeInput, ResourceActionRequest } from './common.js';

export type ResourceInvocationErrorCode = 'invalid_request' | 'invalid_proof' | 'grant_not_active' | 'forbidden' | 'operation_conflict' | 'rate_limited' | 'quota_exceeded' | 'temporarily_unavailable';
export class ResourceInvocationError extends Error { constructor(code: ResourceInvocationErrorCode, status?: number | null); readonly code: ResourceInvocationErrorCode; readonly status: number | null; }
export interface ProtectedResourceClientConfig { readonly registration: AgentRegistration; readonly key: AgentKey; readonly endpoint: { readonly method: 'POST'; readonly url: string }; readonly clock: AgentClock; readonly tls?: { readonly ca: string }; readonly timeoutMs?: number; readonly maxConcurrent?: number; readonly maxOperations?: number; }
export interface ProtectedResourceInvocationResult { readonly http_status: 200 | 202; readonly profile: 'merx-atum-resource-v1-draft.1'; readonly operation_id: string; readonly action_hash: string; readonly intent_hash: string; readonly state: 'succeeded' | 'failed' | 'rejected' | 'expired' | 'prepared' | 'accepted' | 'submitting' | 'unknown'; readonly result: JsonValue | null; }
export interface ProtectedResourceClient { invoke(input: ProtectedRequestChallengeInput): Promise<ProtectedResourceInvocationResult>; close(): Promise<void>; }
export function createProtectedResourceClient(config: ProtectedResourceClientConfig): ProtectedResourceClient;
export type { ResourceActionRequest };
