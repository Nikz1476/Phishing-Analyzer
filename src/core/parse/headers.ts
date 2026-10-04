// Header parsing.
//
// WHY this is more than a regex: real email headers involve line folding,
// RFC 2047 encoded words (often in non-UTF-8 charsets), RFC 2231 parameter
// continuations, comments, quoted display names and groups. A naive
// `split(':')` gets most of these wrong, and getting them wrong is exactly
// how a phishing tool would miss a spoofed From or a mangled attachment name.

import type { Header } from '../types';

/** RFC 5322 unfolding: a CRLF (or LF) followed by whitespace continues a line. */
export function unfold(rawBlock: string): string {
  return rawBlock.replace(/\r\n|\r|\n/g, '\n').replace(/\n[ \t]+/g, ' ');
}

/**
 * Parse a header block into ordered name/value pairs. Order and duplicates
 * are preserved on purpose: Received and Authentication-Results order is the
 * whole ball game for the header forensics.
 */
export function parseHeaderBlock(rawBlock: string): Header[] {
  const normalised = rawBlock.replace(/\r\n|\r/g, '\n');
  const logicalLines = normalised.replace(/\n[ \t]+/g, ' ').split('\n');
  const headers: Header[] = [];
  for (const line of logicalLines) {
    if (!line.trim()) continue;
    const idx = line.indexOf(':');
    if (idx <= 0) continue; // not a header line; ignore rather than throw
    const name = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    headers.push({ name, value });
  }
  return headers;
}

function base64ToBytes(data: string): Uint8Array {
  const cleaned = data.replace(/\s+/g, '');
  const binary = atob(cleaned);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function qToBytes(data: string): Uint8Array {
  const bytes: number[] = [];
  for (let i = 0; i < data.length; i += 1) {
    const ch = data[i]!;
    if (ch === '_') {
      bytes.push(0x20);
    } else if (ch === '=' && i + 2 < data.length) {
      const hex = data.slice(i + 1, i + 3);
      const code = parseInt(hex, 16);
      if (Number.isFinite(code)) {
        bytes.push(code);
        i += 2;
        continue;
      }
      bytes.push(ch.charCodeAt(0));
    } else {
      bytes.push(ch.charCodeAt(0));
    }
  }
  return new Uint8Array(bytes);
}

function decodeBytes(bytes: Uint8Array, charset: string): string {
  try {
    return new TextDecoder(charset || 'utf-8').decode(bytes);
  } catch {
    // Unknown or unsupported charset: fall back to UTF-8 lossless decoding
    // rather than throwing, so a single odd header cannot abort the parse.
    return new TextDecoder('utf-8').decode(bytes);
  }
}

/** Decode one encoded-word body. */
function decodeEncodedWord(
  charset: string,
  encoding: string,
  data: string
): string {
  const cs = charset.toLowerCase().replace(/^"(.*)"$/, '$1');
  if (encoding.toLowerCase() === 'b') return decodeBytes(base64ToBytes(data), cs);
  if (encoding.toLowerCase() === 'q') return decodeBytes(qToBytes(data), cs);
  return data;
}

const ENCODED_WORD_RE = /=\?([^?\s]+)\?([bBqQ])\?([^?]*)\?=/g;

/**
 * Decode RFC 2047 encoded words, including sequences of adjacent words which
 * must be joined WITHOUT the whitespace between them.
 */
export function decodeEncodedWords(value: string): string {
  // Join adjacent encoded words (whitespace between two encoded words is not
  // literal text, per RFC 2047 section 6.2).
  const joined = value.replace(/\?=\s+=\?/g, '?==?');
  return joined.replace(ENCODED_WORD_RE, (_all, charset: string, enc: string, data: string) =>
    decodeEncodedWord(charset, enc, data)
  );
}

/**
 * Decode an RFC 2231 parameter value, e.g.
 *   filename*=UTF-8''invoice%20scan.pdf
 *   filename*0*=UTF-8''long%20name; filename*1*=part2.pdf
 * Returns null when the input is not an RFC 2231 parameter.
 */
export function decodeRfc2231(value: string): string | null {
  const match = /^([^']*)'([^']*)'(.*)$/.exec(value);
  if (!match) return null;
  const charset = match[1] || 'utf-8';
  const encoded = match[3] ?? '';
  const bytes: number[] = [];
  for (let i = 0; i < encoded.length; i += 1) {
    const ch = encoded[i]!;
    if (ch === '%' && i + 2 < encoded.length) {
      const code = parseInt(encoded.slice(i + 1, i + 3), 16);
      if (Number.isFinite(code)) {
        bytes.push(code);
        i += 2;
        continue;
      }
    }
    bytes.push(ch.charCodeAt(0));
  }
  return decodeBytes(new Uint8Array(bytes), charset);
}

/** A parsed mailbox (or group) from an address header. */
export interface ParsedAddress {
  name: string | null;
  address: string | null; // local@domain, lowercased domain
  group?: string;
}

/**
 * Split an address-list header into mailboxes. This is a deliberately small
 * tokeniser, not a full RFC 5322 grammar: it understands quoted strings,
 * angle-addr, comments and groups, which covers real-world headers. Its limits
 * are documented in the Phase 1 tests and in docs/decisions/007.
 */
export function parseAddressList(value: string): ParsedAddress[] {
  const decoded = decodeEncodedWords(value);
  const parts: string[] = [];
  let depthAngle = 0;
  let depthParen = 0;
  let inQuote = false;
  let current = '';
  for (let i = 0; i < decoded.length; i += 1) {
    const ch = decoded[i]!;
    if (ch === '"' && decoded[i - 1] !== '\\') inQuote = !inQuote;
    if (!inQuote) {
      if (ch === '<') depthAngle += 1;
      else if (ch === '>') depthAngle = Math.max(0, depthAngle - 1);
      else if (ch === '(') depthParen += 1;
      else if (ch === ')') depthParen = Math.max(0, depthParen - 1);
      else if (ch === ';') {
        // group terminator: treat as a separator too
      }
    }
    if (ch === ',' && depthAngle === 0 && depthParen === 0 && !inQuote) {
      parts.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  if (current.trim()) parts.push(current);
  return parts.map(parseSingleAddress).filter((a): a is ParsedAddress => a !== null);
}

function stripComments(text: string): { cleaned: string; comment: string } {
  let depth = 0;
  let inQuote = false;
  let cleaned = '';
  let comment = '';
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]!;
    if (ch === '"' && text[i - 1] !== '\\') inQuote = !inQuote;
    if (!inQuote) {
      if (ch === '(') {
        depth += 1;
        continue;
      }
      if (ch === ')') {
        depth = Math.max(0, depth - 1);
        continue;
      }
    }
    if (depth > 0) comment += ch;
    else cleaned += ch;
  }
  return { cleaned: cleaned.trim(), comment: comment.trim() };
}

function parseSingleAddress(raw: string): ParsedAddress | null {
  const text = raw.trim();
  if (!text) return null;

  // Group syntax: "Display Name: addr1, addr2;"
  const groupMatch = /^([^:]*?):\s*(.*)$/.exec(text);
  if (groupMatch && !text.includes('@') === false && groupMatch[1] && !groupMatch[1].includes('@') && !groupMatch[1].includes('<')) {
    // Only treat as a group when there is a real address after the colon.
    if (groupMatch[2] && groupMatch[2].includes('@')) {
      const inner = parseSingleAddress(groupMatch[2]);
      if (inner) return { ...inner, group: groupMatch[1].trim() };
    }
  }

  const angle = /<([^>]*)>/.exec(text);
  if (angle) {
    const address = angle[1]!.trim().toLowerCase();
    const before = stripComments(text.slice(0, angle.index)).cleaned;
    const name = before.replace(/^"|"$/g, '').trim() || null;
    return { name, address: address || null };
  }

  const stripped = stripComments(text).cleaned.replace(/^"|"$/g, '').trim();
  if (stripped.includes('@')) {
    return { name: null, address: stripped.toLowerCase() };
  }
  return null;
}

/** First value of a header (case-insensitive), or null. */
export function headerValue(headers: Header[], name: string): string | null {
  const lower = name.toLowerCase();
  const found = headers.find((h) => h.name.toLowerCase() === lower);
  return found ? found.value : null;
}

/** All values of a header (case-insensitive), in order. */
export function headerValues(headers: Header[], name: string): string[] {
  const lower = name.toLowerCase();
  return headers.filter((h) => h.name.toLowerCase() === lower).map((h) => h.value);
}

/** Build the lowercased-name -> values map used by the rest of the engine. */
export function buildHeaderMap(headers: Header[]): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const h of headers) {
    const key = h.name.toLowerCase();
    const list = map.get(key);
    if (list) list.push(h.value);
    else map.set(key, [h.value]);
  }
  return map;
}

/** Extract the address part of a single From/Reply-To style header. */
export function firstAddress(value: string | null): { name: string | null; address: string | null } | null {
  if (!value) return null;
  const list = parseAddressList(value);
  return list[0] ?? null;
}

/** The domain part of an email address, lowercased. */
export function domainOf(address: string | null | undefined): string | null {
  if (!address) return null;
  const at = address.lastIndexOf('@');
  if (at < 0) return null;
  return address.slice(at + 1).toLowerCase();
}
