import { Codes, TrailGateError } from './errors.ts';

export type SfValue = string | number | boolean | Uint8Array;

export interface SfItem {
  value: SfValue;
  params: Record<string, SfValue>;
}

export interface SfSignatureEntry {
  components: SfItem[];
  params: Record<string, SfValue>;
}

const TOKEN_CHAR = /^[a-zA-Z0-9!#$%&'*+\-.^_`|~:/]/;

function fail(message: string): never {
  throw new TrailGateError(Codes.REQUEST_MALFORMED, message);
}

function skipOws(input: string, pos: number): number {
  while (pos < input.length && (input[pos] === ' ' || input[pos] === '\t')) {
    pos += 1;
  }
  return pos;
}

function parseKey(input: string, pos: number): [string, number] {
  const start = pos;
  while (pos < input.length && /[a-z0-9_\-.*]/.test(input[pos] as string)) {
    pos += 1;
  }
  if (pos === start) {
    fail('expected parameter key');
  }
  return [input.slice(start, pos), pos];
}

function parseToken(input: string, pos: number): [string, number] {
  const start = pos;
  while (pos < input.length && TOKEN_CHAR.test(input[pos] as string)) {
    pos += 1;
  }
  if (pos === start) {
    fail('expected token');
  }
  return [input.slice(start, pos), pos];
}

function parseString(input: string, pos: number): [string, number] {
  if (input[pos] !== '"') {
    fail('expected quoted string');
  }
  pos += 1;
  let out = '';
  while (pos < input.length) {
    const ch = input[pos] as string;
    if (ch === '\\') {
      const next = input[pos + 1];
      if (next !== '"' && next !== '\\') {
        fail('invalid escape in quoted string');
      }
      out += next;
      pos += 2;
      continue;
    }
    if (ch === '"') {
      return [out, pos + 1];
    }
    out += ch;
    pos += 1;
  }
  fail('unterminated quoted string');
}

function parseByteSequence(input: string, pos: number): [Uint8Array, number] {
  if (input[pos] !== ':') {
    fail('expected byte sequence');
  }
  const end = input.indexOf(':', pos + 1);
  if (end < 0) {
    fail('unterminated byte sequence');
  }
  const b64 = input.slice(pos + 1, end);
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) {
    fail('invalid byte sequence encoding');
  }
  return [new Uint8Array(Buffer.from(b64, 'base64')), end + 1];
}

function parseNumber(input: string, pos: number): [number, number] {
  const match = /^-?\d+(\.\d+)?/.exec(input.slice(pos));
  if (match === null) {
    fail('expected number');
  }
  return [Number(match[0]), pos + match[0].length];
}

function parseValue(input: string, pos: number): [SfValue, number] {
  const ch = input[pos];
  if (ch === '"') {
    return parseString(input, pos);
  }
  if (ch === ':') {
    return parseByteSequence(input, pos);
  }
  if (ch === '-' || (ch !== undefined && ch >= '0' && ch <= '9')) {
    return parseNumber(input, pos);
  }
  if (ch === '?') {
    if (input[pos + 1] === '1') {
      return [true, pos + 2];
    }
    if (input[pos + 1] === '0') {
      return [false, pos + 2];
    }
    fail('invalid boolean');
  }
  return parseToken(input, pos);
}

function parseParams(input: string, pos: number): [Record<string, SfValue>, number] {
  const params: Record<string, SfValue> = {};
  while (pos < input.length && input[pos] === ';') {
    pos = skipOws(input, pos + 1);
    const [key, afterKey] = parseKey(input, pos);
    pos = afterKey;
    if (input[pos] === '=') {
      const [value, afterValue] = parseValue(input, pos + 1);
      params[key] = value;
      pos = afterValue;
    } else {
      params[key] = true;
    }
  }
  return [params, pos];
}

function parseInnerList(input: string, pos: number): [SfItem[], number] {
  if (input[pos] !== '(') {
    fail('expected inner list');
  }
  pos += 1;
  const items: SfItem[] = [];
  while (pos < input.length) {
    pos = skipOws(input, pos);
    if (input[pos] === ')') {
      return [items, pos + 1];
    }
    const [value, afterValue] = parseValue(input, pos);
    const [params, afterParams] = parseParams(input, afterValue);
    items.push({ value, params });
    pos = skipOws(input, afterParams);
  }
  fail('unterminated inner list');
}

export function parseSignatureInput(headerValue: string): Map<string, SfSignatureEntry> {
  if (headerValue.trim() === '') {
    fail('empty signature-input field');
  }
  const entries = new Map<string, SfSignatureEntry>();
  let pos = 0;
  while (pos < headerValue.length) {
    pos = skipOws(headerValue, pos);
    const [label, afterLabel] = parseToken(headerValue, pos);
    pos = skipOws(headerValue, afterLabel);
    if (headerValue[pos] !== '=') {
      fail('expected = after signature label');
    }
    pos = skipOws(headerValue, pos + 1);
    const [components, afterList] = parseInnerList(headerValue, pos);
    const [params, afterParams] = parseParams(headerValue, afterList);
    if (entries.has(label)) {
      fail(`duplicate signature label: ${label}`);
    }
    entries.set(label, { components, params });
    pos = skipOws(headerValue, afterParams);
    if (pos >= headerValue.length) {
      break;
    }
    if (headerValue[pos] !== ',') {
      fail('expected comma between signature entries');
    }
    pos += 1;
  }
  return entries;
}

export function parseSignatureField(headerValue: string): Map<string, Uint8Array> {
  const entries = new Map<string, Uint8Array>();
  let pos = 0;
  while (pos < headerValue.length) {
    pos = skipOws(headerValue, pos);
    const [label, afterLabel] = parseToken(headerValue, pos);
    pos = skipOws(headerValue, afterLabel);
    if (headerValue[pos] !== '=') {
      fail('expected = after signature label');
    }
    pos = skipOws(headerValue, pos + 1);
    const [bytes, afterBytes] = parseByteSequence(headerValue, pos);
    entries.set(label, bytes);
    pos = skipOws(headerValue, afterBytes);
    if (pos >= headerValue.length) {
      break;
    }
    if (headerValue[pos] !== ',') {
      fail('expected comma between signature values');
    }
    pos += 1;
  }
  return entries;
}

export function serializeString(value: string): string {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

export function serializeValue(value: SfValue): string {
  if (typeof value === 'string') {
    return serializeString(value);
  }
  if (typeof value === 'boolean') {
    return value ? '?1' : '?0';
  }
  if (typeof value === 'number') {
    return String(value);
  }
  return `:${Buffer.from(value).toString('base64')}:`;
}

export function serializeParams(params: Record<string, SfValue>): string {
  let out = '';
  for (const [key, value] of Object.entries(params)) {
    out += value === true ? `;${key}` : `;${key}=${serializeValue(value)}`;
  }
  return out;
}

export function serializeSignatureParams(entry: SfSignatureEntry): string {
  const items = entry.components
    .map((item) => serializeValue(item.value) + serializeParams(item.params))
    .join(' ');
  return `(${items})${serializeParams(entry.params)}`;
}
