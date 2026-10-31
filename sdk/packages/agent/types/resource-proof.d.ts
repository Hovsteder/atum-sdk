import type { ProtectedRequestSigner, ProtectedRequestSignerConfig } from './common.js';

export function createProtectedRequestSigner(config: ProtectedRequestSignerConfig): ProtectedRequestSigner;

export type {
  BoundedResourceActionRequest, PricesReadActionRequest, ProtectedRequestChallengeInput, ProtectedRequestInput,
  ProtectedRequestSigner, ProtectedRequestSignerConfig, ProtectedResourceEndpoint, ResourceActionRequest,
  ResourceContext, SignatureArtifact,
} from './common.js';
