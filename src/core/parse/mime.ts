// Minimal but careful MIME parser.
//
// WHY hand-written: we need the structure (which part is the text body, which
// are attachments, what the boundary nesting looks like) but we must NEVER
// decode or execute an attachment body - Section 5.3. A generic MIME library
// would happily hand us attachment bytes and encourage exactly that. Here,
// attachments are recorded as metadata only.

import { decodeEncodedWords, decodeRfc2231, parseHeaderBlock } from './headers';
import type { Header } from '../types';

export interface MimePart {
  headers: Header[];
  contentType: string; // lowercased "type/subtype"
  params: Record<string, string>;
  bodyRaw: string; // raw body text (transfer-encoded, undecoded)
  isMultipart: boolean;
  parts: MimePart[];
  disposition: string | null; // "inline" | "attachment" | null
  filename: string | null;
  decodedText: string | null; // present for text/* parts only
}

/** Split "text/html; charset=utf-8" into type + parameters. */
export function parseContentType(value: string | null): { type: string; params: Record<string, string> } {
  if (!value) return { type: 'text/plain', params: {} };
  const segments = splitParams(value);
  const type = (segments.shift() ?? 'text/plain').toLowerCase().trim();
  const params: Record<string, string> = {};
  const continuations: Record<string, { charset: string; data: string }> = {};
  for (const segment of segments) {
    const eq = segment.indexOf('=');
    if (eq < 0) continue;
    const key = segment.slice(0, eq).trim().toLowerCase();
    const val = segment.slice(eq + 1).trim().replace(/^"|"$/g, '');
    const starCont = /^([a-z0-9-]+)\*(\d+)(\*)?$/.exec(key);
    if (/^([a-z0-9-]+)\*$/.test(key)) {
      const decoded = decodeRfc2231(val);
      if (decoded !== null) params[key.replace(/\*$/, '')] = decoded;
      else params[key.replace(/\*$/, '')] = decodeEncodedWords(val);
      continue;
    }
    if (starCont) {
      const base = starCont[1]!;
      const entry = continuations[base] ?? { charset: '', data: '' };
      if (starCont[3] && entry.charset === '') {
        const m = /^([^']*)'([^']*)'(.*)$/.exec(val);
        if (m) entry.charset = m[1] ?? '';
      }
      continuations[base] = entry;
      entry.data += val;
      continue;
    }
    params[key] = decodeEncodedWords(val);
  }
  for (const [base, entry] of Object.entries(continuations)) {
    const decoded = decodeRfc2231(`${entry.charset}''${entry.data}`);
    params[base] = decoded ?? decodeEncodedWords(entry.data);
  }
  return { type, params };
}

/** Split a header value on semicolons that are not inside quotes. */
function splitParams(value: string): string[] {
  const out: string[] = [];
  let current = '';
  let inQuote = false;
  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i]!;
    if (ch === '"' && value[i - 1] !== '\\') inQuote = !inQuote;
    if (ch === ';' && !inQuote) {
      out.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  out.push(current);
  return out;
}

/** Decode quoted-printable body text to bytes, then to a string. */
export function decodeQuotedPrintable(body: string, charset = 'utf-8'): string {
  // Soft line breaks: "=\n" (and "=\r\n") are removed, joining the lines.
  const withoutSoftBreaks = body.replace(/=(?:\r\n|\r|\n)/g, '');
  const bytes: number[] = [];
  for (let i = 0; i < withoutSoftBreaks.length; i += 1) {
    const ch = withoutSoftBreaks[i]!;
    if (ch === '=' && i + 2 < withoutSoftBreaks.length) {
      const code = parseInt(withoutSoftBreaks.slice(i + 1, i + 3), 16);
      if (Number.isFinite(code)) {
        bytes.push(code);
        i += 2;
        continue;
      }
    }
    bytes.push(ch.charCodeAt(0));
  }
  return decodeBytesToText(new Uint8Array(bytes), charset);
}

function decodeBytesToText(bytes: Uint8Array, charset: string): string {
  try {
    return new TextDecoder(charset || 'utf-8').decode(bytes);
  } catch {
    return new TextDecoder('utf-8').decode(bytes);
  }
}

export function decodeBase64Text(body: string, charset = 'utf-8'): string {
  try {
    const binary = atob(body.replace(/\s+/g, ''));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return decodeBytesToText(bytes, charset);
  } catch {
    return '';
  }
}

/** Split an RFC822 blob into headers and body at the first blank line. */
function splitHeaderBody(raw: string): { headerBlock: string; body: string } {
  const normalised = raw.replace(/\r\n|\r/g, '\n');
  const idx = normalised.indexOf('\n\n');
  if (idx < 0) {
    // No blank line: everything is header-ish. Treat a header-looking first
    // line as headers, otherwise treat the whole thing as body (body-only mail).
    if (/^[A-Za-z][A-Za-z0-9-]*:/.test(normalised)) {
      return { headerBlock: normalised, body: '' };
    }
    return { headerBlock: '', body: normalised };
  }
  return { headerBlock: normalised.slice(0, idx), body: normalised.slice(idx + 2) };
}

/** Recursively parse a MIME entity. */
export function parseMime(raw: string): MimePart {
  const { headerBlock, body } = splitHeaderBody(raw);
  const headers = headerBlock ? parseHeaderBlock(headerBlock) : [];
  const ctHeader = headers.find((h) => h.name.toLowerCase() === 'content-type')?.value ?? null;
  const { type, params } = parseContentType(ctHeader);
  const cdHeader = headers.find((h) => h.name.toLowerCase() === 'content-disposition')?.value ?? null;
  const { type: disposition, params: cdParams } = cdHeader
    ? parseContentType(cdHeader)
    : { type: '', params: {} as Record<string, string> };
  const cteHeader = headers.find((h) => h.name.toLowerCase() === 'content-transfer-encoding')?.value ?? '';
  const encoding = cteHeader.trim().toLowerCase().split(/\s*;/)[0] ?? '';
  const charset = params.charset ?? 'utf-8';
  const filename = cdParams.filename ?? params.name ?? null;

  const isMultipart = type.startsWith('multipart/');
  let parts: MimePart[] = [];
  let decodedText: string | null = null;

  if (isMultipart && params.boundary) {
    const boundary = params.boundary;
    parts = splitMultipart(body, boundary).map((chunk) => parseMime(chunk));
  } else if (type.startsWith('text/')) {
    if (encoding === 'quoted-printable') decodedText = decodeQuotedPrintable(body, charset);
    else if (encoding === 'base64') decodedText = decodeBase64Text(body, charset);
    else decodedText = body;
  }
  // Non-text, non-multipart parts are DELIBERATELY not decoded: metadata only.

  return {
    headers,
    contentType: type,
    params,
    bodyRaw: body,
    isMultipart,
    parts,
    disposition: disposition || null,
    filename,
    decodedText
  };
}

/** Split a multipart body on its boundary, discarding the preamble/epilogue. */
export function splitMultipart(body: string, boundary: string): string[] {
  const marker = `--${boundary}`;
  const segments = body.split(marker);
  const parts: string[] = [];
  for (let i = 1; i < segments.length; i += 1) {
    const seg = segments[i]!;
    if (seg.startsWith('--')) break; // closing boundary
    // Strip the leading CRLF after the boundary line.
    parts.push(seg.replace(/^\r?\n/, '').replace(/\r?\n$/, ''));
  }
  return parts;
}