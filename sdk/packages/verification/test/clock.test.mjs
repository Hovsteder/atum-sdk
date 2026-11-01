import assert from 'node:assert/strict';
import { mkdtemp, readFile, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { ObservedSystemClock, createObservedClock, writeClockObservation } from '../src/clock.mjs';

const tracking = ({ leap = 'Normal', stratum = '3', reference = 'Sat Nov 01 00:00:00 2026', offset = '0.001', delay = '0.002', dispersion = '0.003' } = {}) => `Reference ID    : 00000000\nStratum         : ${stratum}\nRef time (UTC)  : ${reference}\nSystem time     : ${offset} seconds fast of NTP time\nRoot delay      : ${delay} seconds\nRoot dispersion : ${dispersion} seconds\nLeap status     : ${leap}\n`;

test('observed chrony clock accepts Normal bounded sample and rejects unhealthy tracking', async () => {
  let now = Date.parse('Sat Nov 01 00:00:01 2026 UTC'); let mono = 1;
  const good = new ObservedSystemClock({ chronycPath: '/bin/chronyc', port: 3231, maxReferenceAgeMs: 2_000 }, { execute: async () => tracking(), now: () => now, monotonic: () => mono++ });
  assert.equal((await good.read()).healthy, true);
  const bad = new ObservedSystemClock({ chronycPath: '/bin/chronyc' }, { execute: async () => tracking({ leap: 'Not synchronised' }), now: () => now, monotonic: () => mono++ });
  assert.equal((await bad.read()).healthy, false);
});

test('reader rejects stale, rollback and symlink observations while atomic writer produces owner file', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'atum-clock-')); const file = join(dir, 'clock.json');
  await writeClockObservation(file, { healthy: true, now_ms: 1000, uncertainty_ms: 2, observed_monotonic_ns: '10' });
  assert.deepEqual(Object.keys(JSON.parse(await readFile(file, 'utf8'))).sort(), ['healthy','now_ms','observed_monotonic_ns','uncertainty_ms']);
  let mono = 10n; let wall = 1000; const read = createObservedClock(file, { maxAgeMs: 10, monotonic: () => mono, wallNow: () => wall });
  assert.equal(read().healthy, true); mono = 20_000_001n; assert.equal(read().healthy, false);
  mono = 10n; wall = 999; assert.equal(read().healthy, false);
  wall = 2000; assert.equal(read().healthy, false);
  const link = join(dir, 'link.json'); await symlink(file, link); assert.equal(createObservedClock(link)().healthy, false);
});
