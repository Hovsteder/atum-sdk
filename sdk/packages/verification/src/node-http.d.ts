import type { IncomingMessage, ServerResponse } from 'node:http';
import type { CurrentAuthorizationConfig, CurrentAuthorizationResult } from './current-authorization.d.ts';
export type CurrentPermission = CurrentAuthorizationResult;
export type ProtectedHandler = Readonly<{ handle(req: IncomingMessage, res: ServerResponse): Promise<void>; close(): Promise<void> }>;
export declare class ProtectedHttpError extends Error { readonly code: string; }
export function createProtectedHttpHandler(config: {
  authorization: CurrentAuthorizationConfig;
  endpoint: { method: string; url: string };
  onAuthorized(permission: CurrentPermission): Promise<object | void> | object | void;
  maxBodyBytes?: number;
  readTimeoutMs?: number;
  maxConcurrent?: number;
}): Promise<ProtectedHandler>;
