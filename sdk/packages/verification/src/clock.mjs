import { execFile } from 'node:child_process';
import { lstat, open, rename, unlink } from 'node:fs/promises';
import { lstatSync, readFileSync } from 'node:fs';
import { dirname, basename } from 'node:path';
import { performance } from 'node:perf_hooks';
import { randomBytes } from 'node:crypto';

const MAX_TIME = 8_640_000_000_000_000;
const SYSTEM = /^([0-9]+(?:\.[0-9]+)?) seconds (?:fast|slow) of NTP time$/;
const SECONDS = /^([0-9]+(?:\.[0-9]+)?) seconds$/;
const STRATUM = /^(?:[1-9]|1[0-5])$/;
const exact = (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v)
  && Object.getPrototypeOf(v) === Object.prototype && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v, low, high) => Number.isSafeInteger(v) && v >= low && v <= high;

function parseTracking(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 16_384) throw new TypeError();
  const values = new Map();
  for (const line of text.split(/\r?\n/)) { const i = line.indexOf(':'); if (i >= 0) { const k = line.slice(0, i).trim(); if (values.has(k)) throw new TypeError(); values.set(k, line.slice(i + 1).trim()); } }
  const sec = value => { const m = SECONDS.exec(value ?? ''); const n = m && Number(m[1]); if (!Number.isFinite(n) || n < 0) throw new TypeError(); return n; };
  if (values.get('Leap status') !== 'Normal' || !STRATUM.test(values.get('Stratum') ?? '')) throw new TypeError();
  const offset = SYSTEM.exec(values.get('System time') ?? ''); const n = offset && Number(offset[1]);
  const reference = Date.parse(`${values.get('Ref time (UTC)')} UTC`);
  if (!Number.isFinite(n) || !Number.isSafeInteger(reference)) throw new TypeError();
  return { offset: n, delay: sec(values.get('Root delay')), dispersion: sec(values.get('Root dispersion')), reference };
}

export class ObservedSystemClock {
  #config; #execute; #now; #monotonic; #previous;
  constructor({ chronycPath = '/usr/bin/chronyc', port = 323, timeoutMs = 2_000, maxReferenceAgeMs = 300_000 } = {}, deps = {}) {
    if (typeof chronycPath !== 'string' || !chronycPath.startsWith('/') || !integer(port, 1, 65535) || !integer(timeoutMs, 1, 5_000) || !integer(maxReferenceAgeMs, 1, 3_600_000) || !exact(deps, Object.keys(deps)) || !Object.keys(deps).every(k => ['execute','now','monotonic'].includes(k))) throw new TypeError('invalid observed clock config');
    this.#config = { chronycPath, port, timeoutMs, maxReferenceAgeMs };
    this.#execute = deps.execute ?? (() => new Promise((resolve, reject) => execFile(chronycPath, ['-n', '-h', '127.0.0.1', '-p', String(port), 'tracking'], { encoding: 'utf8', timeout: timeoutMs, maxBuffer: 16_384, env: { ...process.env, LC_ALL: 'C', LANG: 'C' } }, (e, out) => e ? reject(e) : resolve(out))));
    this.#now = deps.now ?? Date.now; this.#monotonic = deps.monotonic ?? performance.now;
    if (![this.#execute, this.#now, this.#monotonic].every(v => typeof v === 'function')) throw new TypeError('invalid clock dependencies');
  }
  async read() {
    try {
      const wallStart = this.#now(), start = this.#monotonic(), data = parseTracking(await this.#execute()), finished = this.#monotonic(), now = this.#now();
      if (![wallStart, now, start, finished].every(Number.isFinite) || !integer(wallStart, 0, MAX_TIME) || !integer(now, 0, MAX_TIME) || finished < start || now < wallStart || Math.abs((now - wallStart) - (finished - start)) > 50 || now - data.reference < 0 || now - data.reference > this.#config.maxReferenceAgeMs) throw new TypeError();
      const uncertainty = Math.ceil((Math.abs(data.offset) + data.delay / 2 + data.dispersion) * 1000 + (finished - start) + Math.abs((now - wallStart) - (finished - start)));
      if (uncertainty > 1000 || (this.#previous !== undefined && now < this.#previous)) throw new TypeError();
      this.#previous = now; return Object.freeze({ now_ms: now, uncertainty_ms: uncertainty, healthy: true, observed_monotonic_ns: String(process.hrtime.bigint()) });
    } catch { return Object.freeze({ now_ms: 0, uncertainty_ms: 1000, healthy: false, observed_monotonic_ns: String(process.hrtime.bigint()) }); }
  }
}

export async function writeClockObservation(path, observation) {
  if (typeof path !== 'string' || !path.startsWith('/') || !exact(observation, ['now_ms','uncertainty_ms','healthy','observed_monotonic_ns']) || typeof observation.healthy !== 'boolean' || !integer(observation.now_ms, 0, MAX_TIME) || !integer(observation.uncertainty_ms, 0, 1000) || !/^(?:0|[1-9][0-9]*)$/.test(observation.observed_monotonic_ns)) throw new TypeError('invalid clock observation');
  const dir = dirname(path), tmp = `${dir}/.${basename(path)}.${randomBytes(12).toString('hex')}.tmp`;
  let fh;
  try {
    try { const stat = await lstat(path); if (!stat.isFile() || stat.isSymbolicLink()) throw new TypeError('unsafe observation destination'); } catch (e) { if (e?.code !== 'ENOENT') throw e; }
    fh = await open(tmp, 'wx', 0o600); await fh.writeFile(`${JSON.stringify(observation)}\n`); await fh.sync(); await fh.close(); fh = undefined; await rename(tmp, path);
    const d = await open(dir, 'r'); try { await d.sync(); } finally { await d.close(); }
  } catch (e) { try { await fh?.close(); await unlink(tmp); } catch {} throw e; }
}

export function createObservedClock(path, { maxAgeMs = 1_000, monotonic = () => process.hrtime.bigint(), wallNow = Date.now } = {}) {
  if (typeof path !== 'string' || !path.startsWith('/') || !integer(maxAgeMs, 1, 60_000) || typeof monotonic !== 'function' || typeof wallNow !== 'function') throw new TypeError('invalid observed clock config');
  let previous = 0, lastWall; return () => { try { const stat = lstatSync(path); if (!stat.isFile() || stat.isSymbolicLink()) throw new TypeError(); const raw = JSON.parse(readFileSync(path, 'utf8')); if (!exact(raw, ['healthy','now_ms','uncertainty_ms','observed_monotonic_ns']) || raw.healthy !== true || !integer(raw.now_ms, 0, MAX_TIME) || !integer(raw.uncertainty_ms, 0, 1000) || !/^(?:0|[1-9][0-9]*)$/.test(raw.observed_monotonic_ns)) throw new TypeError(); const elapsed = monotonic() - BigInt(raw.observed_monotonic_ns), wall = wallNow(); if (elapsed < 0n || elapsed > BigInt(maxAgeMs) * 1_000_000n || !integer(wall, 0, MAX_TIME) || (lastWall !== undefined && wall < lastWall)) throw new TypeError(); const now = raw.now_ms + Number(elapsed / 1_000_000n); if (Math.abs(wall - now) > 51 || !integer(now, previous, MAX_TIME - raw.uncertainty_ms)) throw new TypeError(); lastWall = wall; previous = now; return Object.freeze({ now_ms: now, uncertainty_ms: raw.uncertainty_ms, healthy: true }); } catch { return Object.freeze({ now_ms: previous, uncertainty_ms: 1000, healthy: false }); } };
}
