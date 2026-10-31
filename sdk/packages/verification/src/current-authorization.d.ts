export type JsonValue = null | boolean | number | string | readonly JsonValue[] | { readonly [key: string]: JsonValue };

export interface ServiceActionRequest {
  readonly action: string;
  readonly parameters: Readonly<Record<string, JsonValue>>;
}

export interface ProtectedRequest {
  readonly authorization: string;
  readonly dpop: string;
  readonly body: string | Uint8Array;
  readonly method: string;
  readonly url: string;
}

export interface CurrentAuthorizationResult<Action extends ServiceActionRequest = ServiceActionRequest> {
  readonly authorization_effect: 'current_permission';
  readonly requires_resource_acceptance: true;
  readonly proof_verified: true;
  readonly scoped_subject: string;
  readonly agent_key_thumbprint: string;
  readonly client_id: string;
  readonly context: Readonly<Record<string, JsonValue>>;
  readonly action_request: Action;
  readonly intent_hash: string;
  readonly proof_jti: string;
  readonly admission_id: string;
  readonly permissions: readonly Readonly<Record<string, JsonValue>>[];
  /** Original owner-approved cap. This is never a remaining-use counter. */
  readonly grant_limit: number;
  readonly token_expires_at_ms: number;
  readonly grant_expires_at_ms: number;
  readonly snapshot_valid_until_ms: number;
  readonly evaluated_at_ms: number;
  readonly evaluated_uncertainty_ms: number;
  readonly acceptance_expires_at_ms: number;
  readonly first_submit_expires_at_ms: number;
}

export interface CurrentAuthorizationVerifier {
  verifyCurrent<Action extends ServiceActionRequest = ServiceActionRequest>(request: ProtectedRequest): Promise<CurrentAuthorizationResult<Action>>;
  close(): Promise<void>;
}

export type AuthorityTransport = {
  readonly tls: { readonly ca: string; readonly cert: string; readonly key: string };
  readonly serviceCredential?: never;
  readonly https?: never;
} | {
  /** One-time-displayed, rotatable service credential from the ATUM catalog. */
  readonly serviceCredential: string;
  /** Omit `ca` to use the host system trust store. */
  readonly https: { readonly ca?: string };
  readonly tls?: never;
};

export interface CurrentAuthorizationConfig {
  readonly registration: Readonly<Record<string, JsonValue>>;
  readonly descriptor?: Readonly<Record<string, JsonValue>>;
  readonly clock: () => { readonly now_ms: number; readonly uncertainty_ms: number; readonly healthy: boolean };
  readonly proof: {
    readonly issuerKeys: readonly Readonly<Record<string, JsonValue>>[];
    readonly endpoint: { readonly method: string; readonly url: string };
    readonly replayStore: { consume(input: Readonly<Record<string, JsonValue>>): boolean | Promise<boolean> };
  };
  readonly authority: AuthorityTransport & {
    readonly issuerKeys: Readonly<Record<string, Readonly<Record<string, JsonValue>>>>;
    readonly evidencePolicy: Readonly<Record<string, JsonValue>> | null;
    readonly baseUrl: string;
    readonly timeoutMs: number;
    readonly maxConcurrent: number;
  };
}

export declare function createCurrentAuthorizationVerifier(config: CurrentAuthorizationConfig): Promise<CurrentAuthorizationVerifier>;

export declare class VerificationError extends Error { readonly code: string; }
export declare class AuthorityError extends Error { readonly code: string; }
export declare class ResourceTransportError extends Error { readonly code: string; }
