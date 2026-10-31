import assert from 'node:assert/strict';
import test from 'node:test';

import { canonical, parseClosedJson, snapshotData } from '../src/strict.mjs';

test('strict parser preserves bounded integer JSON and canonical sorts object keys recursively', () => {
  const parsed = parseClosedJson(new TextEncoder().encode('{"z":1,"a":[-2,{"b":null,"a":true}]}'));
  assert.deepEqual(parsed, { z: 1, a: [-2, { b: null, a: true }] });
  assert.equal(canonical(parsed), '{"a":[-2,{"a":true,"b":null}],"z":1}');
});

test('strict parser rejects input JSON whose syntax can hide or round security fields', () => {
  const invalid = [
    '{"x":1,"x":2}',
    '{"x":1,"\\u0078":2}',
    '{"__proto__":1}',
    '{"constructor":1}',
    '{"prototype":1}',
    '{/*comment*/"x":1}',
    '{"x":1,}',
    '[1]',
    '{"x":1.0}',
    '{"x":1e0}',
    '{"x":1.5}',
    '{"x":-0}',
    '{"x":9007199254740992}',
    '{"x":1e400}',
    `{"x":${'['.repeat(12)}0${']'.repeat(12)}}`,
    new Uint8Array([0x7b, 0x22, 0x78, 0x22, 0x3a, 0xc3, 0x28, 0x7d]),
  ];
  for (const value of invalid) assert.throws(() => parseClosedJson(value), TypeError, String(value).slice(0, 40));
});

test('strict parser counts UTF-8 bytes and snapshots a mutable byte input', () => {
  const bytes = new TextEncoder().encode('{"x":"é"}');
  assert.deepEqual(parseClosedJson(bytes, bytes.byteLength), { x: 'é' });
  assert.throws(() => parseClosedJson(bytes, bytes.byteLength - 1), TypeError);
  assert.throws(() => parseClosedJson('{"x":"é"}', bytes.byteLength - 1), TypeError);
  assert.throws(() => parseClosedJson('{"x":1}', 32769), TypeError);
});

test('strict byte snapshots do not dispatch typed-array species', () => {
  let speciesCalls = 0;
  class HostileBytes extends Uint8Array {
    static get [Symbol.species]() {
      speciesCalls += 1;
      throw new Error('species must not run');
    }
  }
  const bytes = new HostileBytes(new TextEncoder().encode('{"x":1}'));
  assert.deepEqual(parseClosedJson(bytes), { x: 1 });
  assert.equal(speciesCalls, 0);
});

test('canonical rejects accessors, symbols, sparse arrays and non-plain objects without invoking getters', () => {
  let calls = 0;
  const accessor = {};
  Object.defineProperty(accessor, 'x', { enumerable: true, get() { calls += 1; return 1; } });
  const symbol = { x: 1 };
  symbol[Symbol('hidden')] = 2;
  const sparse = [];
  sparse.length = 1;
  for (const value of [accessor, symbol, sparse, new Date(0), Object.create(null)]) {
    assert.throws(() => canonical(value), TypeError);
  }
  assert.equal(calls, 0);
});

test('snapshotData captures nested descriptor values before mutation and deeply freezes its copy', () => {
  const source = { z: [{ b: 2 }], a: 1 };
  const saved = snapshotData(source);
  source.z[0].b = 9;
  source.z.push({ b: 3 });
  assert.deepEqual(saved, { z: [{ b: 2 }], a: 1 });
  assert.equal(Object.isFrozen(saved), true);
  assert.equal(Object.isFrozen(saved.z), true);
  assert.equal(Object.isFrozen(saved.z[0]), true);
  assert.throws(() => { saved.a = 3; }, TypeError);
});

test('snapshotData validates the same descriptor values that it returns', () => {
  let calls = 0;
  const source = new Proxy({ x: 1 }, {
    getOwnPropertyDescriptor(target, key) {
      if (key === 'x') {
        calls += 1;
        return { value: calls === 1 ? 1 : Number.NaN, enumerable: true, configurable: true, writable: true };
      }
      return Reflect.getOwnPropertyDescriptor(target, key);
    },
  });
  const saved = snapshotData(source);
  assert.deepEqual(saved, { x: 1 });
  assert.equal(calls, 1);
});

test('snapshotData enforces its aggregate byte budget while capturing a shared graph', () => {
  let reads = 0;
  const leaf = new Proxy({ x: 1 }, {
    getOwnPropertyDescriptor(target, key) {
      if (key === 'x') reads += 1;
      return Reflect.getOwnPropertyDescriptor(target, key);
    },
  });
  let tree = leaf;
  for (let depth = 0; depth < 7; depth += 1) tree = Array(4).fill(tree);
  assert.throws(() => snapshotData({ tree }), (error) => error instanceof TypeError && error.message === 'invalid input');
  assert.ok(reads < 5_000, `capture traversed ${reads} repeated leaves before enforcing its byte budget`);
});

test('canonical and snapshot bounds reject deep or huge containers with safe TypeError', () => {
  let deep = { x: 1 };
  for (let index = 0; index < 13; index += 1) deep = { x: deep };
  const sparse = [];
  sparse.length = 1_000_000_000;
  const wide = {};
  for (let index = 0; index < 9000; index += 1) wide[`k${index}`] = index;
  for (const value of [deep, sparse, wide, { x: 'a'.repeat(32769) }]) {
    assert.throws(() => canonical(value), (error) => error instanceof TypeError && error.message === 'invalid input');
    assert.throws(() => snapshotData(value), (error) => error instanceof TypeError && error.message === 'invalid input');
  }
});
