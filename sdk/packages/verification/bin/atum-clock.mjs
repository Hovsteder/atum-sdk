#!/usr/bin/env node
import { ObservedSystemClock, writeClockObservation } from '../src/clock.mjs';
const file = process.env.ATUM_CLOCK_OBSERVATION_FILE;
if (!file) throw new Error('ATUM_CLOCK_OBSERVATION_FILE is required');
const clock = new ObservedSystemClock({ chronycPath: process.env.ATUM_CHRONYC_PATH ?? '/usr/bin/chronyc', port: Number(process.env.ATUM_CHRONYC_PORT ?? '323'), maxReferenceAgeMs: Number(process.env.ATUM_CLOCK_MAX_REFERENCE_AGE_MS ?? '300000') });
const interval = Number(process.env.ATUM_CLOCK_INTERVAL_MS ?? '250');
if (!Number.isSafeInteger(interval) || interval < 25 || interval > 60_000) throw new TypeError('invalid clock interval');
let stopped = false;
let running = false;
async function tick() { if (running || stopped) return; running = true; try { const sample = await clock.read(); await writeClockObservation(file, sample); if (!sample.healthy) process.stderr.write('atum-clock: chrony observation unhealthy\n'); } catch (e) { process.stderr.write(`atum-clock: ${e.message}\n`); } finally { running = false; } }
await tick(); const timer = setInterval(() => { void tick(); }, interval);
for (const signal of ['SIGINT','SIGTERM']) process.once(signal, () => { if (!stopped) { stopped = true; clearInterval(timer); } });
