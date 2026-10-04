// Top-level message parsing: decide what kind of input we were given, then
// pull out the text body, the HTML body, and the attachment list.

import { buildHeaderMap, parseHeaderBlock } from './headers';
import { parseMime, type MimePart } from './mime';
import type { AttachmentInfo, ParsedMessage } from '../types';

/** True when the input starts with a plausible RFC822 header block. */
export function detectHeaderBlock(raw: string): boolean {
  const normalised = raw.replace(/\r\n|\r/g, '\n');
  const firstLine = normalised.split('\n', 1)[0] ?? '';
  if (!/^[A-Za-z][A-Za-z0-9-]*:/.test(firstLine)) return false;
  // Require a blank line separating headers from body, OR at least two
  // header-looking lines, to avoid misreading a one-line "Note: hello" body.
  if (normalised.includes('\n\n')) return true;
  const headerLines = normalised.split('\n').filter((l) => /^[A-Za-z][A-Za-z0-9-]*:/.test(l));
  return headerLines.length >= 2;
}

function looksLikeHtml(raw: string): boolean {
  return /<\s*(html|body|div|p|a|span|table|img|br)\b/i.test(raw);
}

function collectParts(part: MimePart, acc: { text: string[]; html: string[]; attachments: AttachmentInfo[] }): void {
  if (part.isMultipart) {
    for (const child of part.parts) collectParts(child, acc);
    return;
  }
  const isAttachment = part.disposition === 'attachment' || (part.filename !== null && !part.contentType.startsWith('multipart/'));
  if (isAttachment) {
    acc.attachments.push({
      filename: part.filename,
      contentType: part.contentType,
      // Size of the transfer-encoded body as we received it; we never decode
      // attachment content, so this is an upper-bound approximation.
      size: part.bodyRaw.length,
      encoding: part.headers.find((h) => h.name.toLowerCase() === 'content-transfer-encoding')?.value ?? null
    });
    return;
  }
  if (part.contentType === 'text/html' && part.decodedText !== null) acc.html.push(part.decodedText);
  else if (part.contentType.startsWith('text/') && part.decodedText !== null) acc.text.push(part.decodedText);
}

/** Parse the pasted input into headers, body text, HTML body and attachments. */
export function parseMessage(raw: string): ParsedMessage {
  const warnings: string[] = [];
  const isRaw = detectHeaderBlock(raw);

  if (!isRaw) {
    // Body-only input. It may still be an HTML snippet.
    const html = looksLikeHtml(raw) ? raw : null;
    return {
      isRaw: false,
      headers: [],
      headerMap: new Map(),
      bodyText: html ? stripHtmlToText(html) : raw,
      bodyHtml: html,
      attachments: [],
      rawMime: raw,
      warnings
    };
  }

  let top: MimePart;
  try {
    top = parseMime(raw);
  } catch (err) {
    // Malformed input must never throw - return a partial parse plus a warning.
    warnings.push(`MIME parse error: ${(err as Error).message}`);
    const headers = parseHeaderBlock(raw.replace(/\r\n|\r/g, '\n').split('\n\n')[0] ?? '');
    return {
      isRaw: true,
      headers,
      headerMap: buildHeaderMap(headers),
      bodyText: raw,
      bodyHtml: null,
      attachments: [],
      rawMime: raw,
      warnings
    };
  }

  const headers = top.headers;
  const acc = { text: [] as string[], html: [] as string[], attachments: [] as AttachmentInfo[] };
  collectParts(top, acc);

  for (const a of acc.attachments) {
    if (a.filename === null && (a.contentType === null || a.contentType === '')) {
      warnings.push('Attachment with no filename or content-type');
    }
  }

  const bodyText = acc.text.join('\n\n') || (acc.html.length === 0 ? top.bodyRaw : '');
  const bodyHtml = acc.html.length > 0 ? acc.html.join('\n') : null;

  return {
    isRaw: true,
    headers,
    headerMap: buildHeaderMap(headers),
    bodyText: acc.html.length > 0 ? bodyText || stripHtmlToText(acc.html.join('\n')) : bodyText,
    bodyHtml,
    attachments: acc.attachments,
    rawMime: raw,
    warnings
  };
}

/**
 * Crude HTML-to-text for the plain-text fallback. WHY crude: the real text we
 * match against comes from the dedicated, DOMParser-based HTML extractor. This
 * is only a safety net so we always have *something* readable.
 */
export function stripHtmlToText(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|tr|li|h[1-6])>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/\s+\n/g, '\n')
    .trim();
}