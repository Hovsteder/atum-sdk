export type ClockSample = Readonly<{ now_ms: number; uncertainty_ms: number; healthy: boolean }>;
export type ClockObservation = ClockSample & Readonly<{ observed_monotonic_ns: string }>;
export class ObservedSystemClock {
  constructor(config?: { chronycPath?: string; port?: number; timeoutMs?: number; maxReferenceAgeMs?: number });
  read(): Promise<ClockObservation>;
}
export function writeClockObservation(path: string, observation: ClockObservation): Promise<void>;
export function createObservedClock(path: string, options?: { maxAgeMs?: number; monotonic?: () => bigint; wallNow?: () => number }): () => ClockSample;
