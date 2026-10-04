// URL extraction from text and HTML.
//
// WHY careful trailing-punctuation handling: a link at the end of a sentence
// ends with '.' that is NOT part of the URL, but a URL can legitimately end
// with ')'. Getting this wrong either breaks real URLs or invents fake hosts.

import { defang } from '../url/defang';
import type { ExtractedUrl } from '../types';

/** Trim sentence punctuation from the end of a candidate URL. */
export function trimUrlTail(candidate: string): string {
  let out = candidate.replace(/[.,;:!?"'\]>]+$/g, '');
  // Balance parentheses: drop a trailing ')' only if there is no matching '('.
  while (out.endsWith(')')) {
    const opens = (out.match(/\(/g) ?? []).length;
    const closes = (out.match(/\)/g) ?? []).length;
    if (closes > opens) out = out.slice(0, -1);
    else break;
  }
  return out;
}

const SCHEME_RE = /\b(?:https?|hxxps?|ftp|ftps|data|javascript|vbscript):\/\/[^\s<>"'()]+/gi;
const BARE_WWW_RE = /\bwww\.[a-z0-9-]+(?:\.[a-z0-9-]+)+[^\s<>"']*/gi;
const MARKDOWN_RE = /\[([^\]]*)\]\((?:<)?([^)\s>]+)(?:>)?\)/g;

function push(list: ExtractedUrl[], raw: string, source: ExtractedUrl['source'], displayText?: string): void {
  const trimmed = trimUrlTail(raw);
  if (!trimmed) return;
  if (!/^(?:https?|hxxps?|ftp|ftps|data|javascript|vbscript):\/\//i.test(trimmed) && !/^www\./i.test(trimmed)) return;
  const entry: ExtractedUrl = {
    raw: trimmed,
    defanged: defang(trimmed),
    source
  };
  if (displayText !== undefined) entry.displayText = displayText;
  list.push(entry);
}

/** Extract plain-text URLs (scheme URLs, bare www, markdown links). */
export function extractUrlsFromText(text: string): ExtractedUrl[] {
  const found: ExtractedUrl[] = [];

  MARKDOWN_RE.lastIndex = 0;
  let md: RegExpExecArray | null;
  while ((md = MARKDOWN_RE.exec(text)) !== null) {
    push(found, md[2]!, 'markdown', md[1]!);
  }

  SCHEME_RE.lastIndex = 0;
  let scheme: RegExpExecArray | null;
  while ((scheme = SCHEME_RE.exec(text)) !== null) {
    push(found, scheme[0], 'body-text');
  }

  BARE_WWW_RE.lastIndex = 0;
  let www: RegExpExecArray | null;
  while ((www = BARE_WWW_RE.exec(text)) !== null) {
    push(found, `http://${www[0]}`, 'body-text');
  }

  return found;
}

/** Merge HTML anchors and text URLs into one deduped list. */
export function mergeExtractedUrls(
  anchors: Array<{ href: string; text: string }>,
  textUrls: ExtractedUrl[]
): ExtractedUrl[] {
  const out: ExtractedUrl[] = [];
  for (const anchor of anchors) {
    if (!anchor.href) continue;
    // Skip in-page anchors and non-URL schemes except the dangerous ones.
    if (/^#/.test(anchor.href)) continue;
    const source: ExtractedUrl['source'] = 'html-href';
    const entry: ExtractedUrl = {
      raw: anchor.href,
      defanged: defang(anchor.href),
      source
    };
    if (anchor.text) entry.displayText = anchor.text;
    out.push(entry);
  }
  out.push(...textUrls);
  return out;
}

/** Dedupe by refanged-normalised URL while keeping the first occurrence. */
export function dedupeUrls(urls: ExtractedUrl[]): ExtractedUrl[] {
  const seen = new Set<string>();
  const out: ExtractedUrl[] = [];
  for (const url of urls) {
    const key = url.raw.trim().toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(url);
  }
  return out;
}