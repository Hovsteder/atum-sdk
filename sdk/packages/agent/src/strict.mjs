import { visit } from 'jsonc-parser';

const PROTOTYPE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_JSON_BYTES = 32 * 1024;
const MAX_CONTAINER_ITEMS = 8192;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const typedArrayByteLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength').get;

function invalid(message = 'invalid input') { throw new TypeError(message); }

function byteSnapshot(input, maxBytes) {
  if (typeof input === 'string') {
    if (input.length > maxBytes) invalid();
    let bytes;
    try { bytes = encoder.encode(input); } catch { invalid(); }
    if (bytes.byteLength > maxBytes) invalid();
    try { if (decoder.decode(bytes) !== input) invalid(); } catch { invalid(); }
    return bytes;
  }
  if (!ArrayBuffer.isView(input) || !(input instanceof Uint8Array)) invalid();
  let bytes;
  try {
    if (typedArrayByteLength.call(input) > maxBytes) invalid();
    bytes = new Uint8Array(input);
  } catch { invalid(); }
  return bytes;
}

function scan(text) {
  const objects = [];
  let depth = 0;
  visit(text, {
    onObjectBegin() { depth += 1; if (depth > 12) invalid(); objects.push(new Set()); },
    onObjectProperty(key) {
      const current = objects.at(-1);
      if (!current || current.has(key) || PROTOTYPE_KEYS.has(key)) invalid();
      current.add(key);
    },
    onObjectEnd() { objects.pop(); depth -= 1; },
    onArrayBegin() { depth += 1; if (depth > 12) invalid(); },
    onArrayEnd() { depth -= 1; },
    onLiteralValue(value, offset, length) {
      if (typeof value !== 'number') return;
      const raw = text.slice(offset, offset + length);
      if (!/^-?(?:0|[1-9][0-9]*)$/.test(raw) || Object.is(value, -0) || !Number.isSafeInteger(value)) invalid();
    },
    onComment() { invalid(); },
    onError() { invalid(); },
  }, { allowTrailingComma: false, disallowComments: true, allowEmptyContent: false });
}

function descriptors(value) {
  let keys; let values;
  try { keys = Reflect.ownKeys(value); values = Object.getOwnPropertyDescriptors(value); } catch { invalid(); }
  if (keys.some((key) => typeof key !== 'string') || Object.keys(values).length !== keys.length) invalid();
  return { keys, values };
}

function emit(state, value) {
  if (value.length > state.remaining) invalid();
  const size = encoder.encode(value).byteLength;
  if (size > state.remaining) invalid();
  state.remaining -= size;
  return value;
}

function canonicalValue(value, active, depth, state) {
  if (depth > 12) invalid();
  if (value === null || typeof value === 'boolean') return emit(state, JSON.stringify(value));
  if (typeof value === 'string') {
    if (value.length > MAX_JSON_BYTES) invalid();
    const bytes = encoder.encode(value);
    try { if (decoder.decode(bytes) !== value) invalid(); } catch { invalid(); }
    return emit(state, JSON.stringify(value));
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) invalid();
    return emit(state, String(value));
  }
  if (value === null || typeof value !== 'object' || active.has(value)) invalid();
  active.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) invalid();
      const { keys, values } = descriptors(value);
      const length = values.length;
      if (!length || !Object.hasOwn(length, 'value') || !Number.isSafeInteger(length.value) || length.value < 0 || length.value > MAX_CONTAINER_ITEMS) invalid();
      const expected = Array.from({ length: length.value }, (_, index) => String(index));
      if (keys.length !== expected.length + 1 || keys.at(-1) !== 'length'
          || expected.some((key, index) => keys[index] !== key)) invalid();
      const parts = [emit(state, '[')];
      expected.forEach((key, index) => {
        const descriptor = values[key];
        if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) invalid();
        if (index) parts.push(emit(state, ','));
        parts.push(canonicalValue(descriptor.value, active, depth + 1, state));
      });
      parts.push(emit(state, ']'));
      return parts.join('');
    }
    if (Object.getPrototypeOf(value) !== Object.prototype) invalid();
    const { keys, values } = descriptors(value);
    if (keys.length > MAX_CONTAINER_ITEMS || keys.some((key) => PROTOTYPE_KEYS.has(key) || !/^[\x20-\x7e]+$/.test(key))) invalid();
    keys.sort();
    const parts = [emit(state, '{')];
    keys.forEach((key, index) => {
      const descriptor = values[key];
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) invalid();
      if (index) parts.push(emit(state, ','));
      parts.push(emit(state, `${JSON.stringify(key)}:`));
      parts.push(canonicalValue(descriptor.value, active, depth + 1, state));
    });
    parts.push(emit(state, '}'));
    return parts.join('');
  } finally {
    active.delete(value);
  }
}

function consume(state, size) {
  if (!Number.isSafeInteger(size) || size < 0 || size > state.remaining) invalid();
  state.remaining -= size;
}

function snapshotString(value, state) {
  if (value.length > MAX_JSON_BYTES) invalid();
  let bytes; let encoded;
  try {
    bytes = encoder.encode(value);
    if (decoder.decode(bytes) !== value) invalid();
    encoded = encoder.encode(JSON.stringify(value)).byteLength;
  } catch { invalid(); }
  consume(state, encoded);
  return value;
}

function snapshotValue(value, active, depth, state) {
  if (depth > 12) invalid();
  if (value === null) { consume(state, 4); return value; }
  if (typeof value === 'boolean') { consume(state, value ? 4 : 5); return value; }
  if (typeof value === 'string') return snapshotString(value, state);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) invalid();
    consume(state, String(value).length);
    return value;
  }
  if (value === null || typeof value !== 'object' || active.has(value)) invalid();
  active.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) invalid();
      const { keys, values } = descriptors(value);
      const length = values.length;
      if (!length || !Object.hasOwn(length, 'value') || !Number.isSafeInteger(length.value) || length.value < 0 || length.value > MAX_CONTAINER_ITEMS) invalid();
      const expected = Array.from({ length: length.value }, (_, index) => String(index));
      if (keys.length !== expected.length + 1 || keys.at(-1) !== 'length'
          || expected.some((key, index) => keys[index] !== key)) invalid();
      consume(state, 2 + Math.max(0, expected.length - 1));
      return Object.freeze(expected.map((key) => {
        const descriptor = values[key];
        if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) invalid();
        return snapshotValue(descriptor.value, active, depth + 1, state);
      }));
    }
    if (Object.getPrototypeOf(value) !== Object.prototype) invalid();
    const { keys, values } = descriptors(value);
    if (keys.length > MAX_CONTAINER_ITEMS || keys.some((key) => PROTOTYPE_KEYS.has(key) || !/^[\x20-\x7e]+$/.test(key))) invalid();
    consume(state, 2 + Math.max(0, keys.length - 1));
    const result = {};
    for (const key of keys) {
      const descriptor = values[key];
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) invalid();
      consume(state, encoder.encode(JSON.stringify(key)).byteLength + 1);
      result[key] = snapshotValue(descriptor.value, active, depth + 1, state);
    }
    return Object.freeze(result);
  } finally {
    active.delete(value);
  }
}

export function parseClosedJson(input, maxBytes = MAX_JSON_BYTES) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || maxBytes > MAX_JSON_BYTES) invalid();
  const bytes = byteSnapshot(input, maxBytes);
  let text;
  try { text = decoder.decode(bytes); } catch { invalid(); }
  if (text.charCodeAt(0) === 0xfeff) invalid();
  scan(text);
  let parsed;
  try { parsed = JSON.parse(text); } catch { invalid(); }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed) || Object.getPrototypeOf(parsed) !== Object.prototype) invalid();
  canonical(parsed);
  return parsed;
}

export function canonical(value) {
  return canonicalValue(value, new WeakSet(), 0, { remaining: MAX_JSON_BYTES });
}

export function snapshotData(value) {
  const snapshot = snapshotValue(value, new WeakSet(), 0, { remaining: MAX_JSON_BYTES });
  canonical(snapshot);
  return snapshot;
}
