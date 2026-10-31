import { readFileSync } from 'node:fs';

const MAX_TIME = 8_640_000_000_000_000;

export function createObservedClock(path, { maxAgeMs = 1_000, monotonic = () => process.hrtime.bigint() } = {}) {
  if (typeof path !== 'string' || !path.startsWith('/') || !Number.isSafeInteger(maxAgeMs) || maxAgeMs < 1 || maxAgeMs > 60_000
      || typeof monotonic !== 'function') throw new TypeError('invalid observed clock config');
  let previous = 0;
  return () => {
    try {
      const raw = JSON.parse(readFileSync(path, 'utf8'));
      if (!raw || Object.getPrototypeOf(raw) !== Object.prototype
          || Object.keys(raw).sort().join(',') !== 'healthy,now_ms,observed_monotonic_ns,uncertainty_ms'
          || raw.healthy !== true || !Number.isSafeInteger(raw.now_ms) || raw.now_ms < 0 || raw.now_ms > MAX_TIME
          || !Number.isSafeInteger(raw.uncertainty_ms) || raw.uncertainty_ms < 0 || raw.uncertainty_ms > 1_000
          || typeof raw.observed_monotonic_ns !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(raw.observed_monotonic_ns)) throw new TypeError();
      const elapsedNs = monotonic() - BigInt(raw.observed_monotonic_ns);
      if (elapsedNs < 0n || elapsedNs > BigInt(maxAgeMs) * 1_000_000n) throw new TypeError();
      const elapsedMs = Number(elapsedNs / 1_000_000n); const now = raw.now_ms + elapsedMs;
      if (!Number.isSafeInteger(now) || now > MAX_TIME || now < previous || now > MAX_TIME - raw.uncertainty_ms) throw new TypeError();
      previous = now;
      return Object.freeze({ now_ms: now, uncertainty_ms: raw.uncertainty_ms, healthy: true });
    } catch {
      return Object.freeze({ now_ms: previous, uncertainty_ms: 1_000, healthy: false });
    }
  };
}
