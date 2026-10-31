import type { ProtectedRequestSigner, ProtectedRequestSignerConfig } from './common.js';

export function createProtectedRequestSigner(config: ProtectedRequestSignerConfig): ProtectedRequestSigner;

export type {
  BoundedResourceActionRequest, EnergyPurchaseActionRequest, GenericResourceContext, GenericServiceActionRequest, PricesReadActionRequest, ProtectedRequestChallengeInput, ProtectedRequestInput,
  ProtectedRequestSigner, ProtectedRequestSignerConfig, ProtectedResourceEndpoint, ResourceActionRequest,
  EnergyResourceContext, ResourceContext, SandboxResourceContext, ServiceActionDescriptor, SignatureArtifact,
} from './common.js';
