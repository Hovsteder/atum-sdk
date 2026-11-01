import type { IncomingMessage, ServerResponse } from 'node:http';
export type CurrentPermission = Readonly<Record<string, unknown>>;
export type ProtectedHandler = Readonly<{ handle(req: IncomingMessage, res: ServerResponse): Promise<void>; close(): Promise<void> }>;
export function createProtectedHttpHandler(config: {
  authorization: object;
  endpoint: { method: string; url: string };
  onAuthorized(permission: CurrentPermission): Promise<object | void> | object | void;
  maxBodyBytes?: number;
  readTimeoutMs?: number;
}): Promise<ProtectedHandler>;
