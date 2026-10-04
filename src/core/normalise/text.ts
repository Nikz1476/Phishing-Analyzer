// Text normalisation with a parallel offset map back to the original text.
//
// WHY an offset map: rule matches happen on a cleaned-up copy of the message,
// but evidence must be highlighted in exactly what the user pasted. Without
// the map, spans would point at the wrong characters (or into the normalised
// string, which the user never saw).
//
// WHY normalise at all (Section 5.5): attackers hide words behind zero-width
// characters, HTML entities, homoglyphs and defanging. If rules ran on the
// raw text, every one of those tricks would defeat them.

import { confusablesSingle } from '../data';
import type { NormalisedText } from '../types';

interface Mapped {
  text: string;
  map: number[];
}

type Replacer = string | ((match: RegExpExecArray) => string);

/**
 * Apply a global regex to `text`, carrying the offset map along. Characters
 * produced by a replacement all point at the ORIGINAL index of the first
 * consumed character (good enough to anchor a highlight; the end offset uses
 * the last consumed char + 1).
 */
function applyPattern(re: RegExp, source: Mapped, repl: Replacer): Mapped {
  const out: string[] = [];
  const map: number[] = [];
  const text = source.text;
  let last = 0;
  re.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    for (let i = last; i < m.index; i += 1) {
      out.push(text[i]!);
      map.push(source.map[i]!);
    }
    const base = source.map[m.index] ?? source.map[source.map.length - 1] ?? 0;
    const emitted = typeof repl === 'function' ? repl(m) : repl;
    for (const ch of emitted) {
      out.push(ch);
      map.push(base);
    }
    last = m.index + m[0].length;
    if (m[0].length === 0) re.lastIndex += 1; // avoid infinite loop on empty matches
  }
  for (let i = last; i < text.length; i += 1) {
    out.push(text[i]!);
    map.push(source.map[i]!);
  }
  return { text: out.join(''), map };
}


const NAMED_ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', copy: '\u00a9',
  reg: '\u00ae', trade: '\u2122', hellip: '\u2026', mdash: '\u2014', ndash: '\u2013',
  rsquo: '\u2019', lsquo: '\u2018', rdquo: '\u201d', ldquo: '\u201c', bull: '\u2022',
  euro: '\u20ac', pound: '\u00a3', middot: '\u00b7', not: '\u00ac', times: '\u00d7',
  zwnj: '', zwj: '', shy: ''
};

function safeFromCodePoint(code: number): string {
  if (code < 0 || code > 0x10ffff) return '';
  try {
    return String.fromCodePoint(code);
  } catch {
    return '';
  }
}

function decodeEntity(m: RegExpExecArray): string {
  const body = m[1] ?? '';
  if (body.startsWith('#x') || body.startsWith('#X')) {
    const code = parseInt(body.slice(2), 16);
    return Number.isFinite(code) ? safeFromCodePoint(code) : m[0];
  }
  if (body.startsWith('#')) {
    const code = parseInt(body.slice(1), 10);
    return Number.isFinite(code) ? safeFromCodePoint(code) : m[0];
  }
  const named = NAMED_ENTITIES[body.toLowerCase()];
  return named ?? m[0];
}

/** HTML entity, then common defanging, then NFKC, then invisible removal. */
function normaliseChain(original: string): { mapped: Mapped; zeroWidth: number } {
  let cur: Mapped = {
    text: original,
    map: Array.from({ length: original.length }, (_, i) => i)
  };

  // 1. HTML entities (&amp;, &#x27;, ...).
  cur = applyPattern(/&(#x[0-9a-f]+|#\d+|[a-z][a-z0-9]*);/gi, cur, decodeEntity);

  // 2. Un-defang: hxxp(s), [.], (.), [at], [@], [:], [://].
  cur = applyPattern(/hxxps?/gi, cur, (m) => m[0].toLowerCase().replace('xx', 'tt'));
  cur = applyPattern(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[\s*dot\s*\]|\(\s*dot\s*\)/gi, cur, '.');
  cur = applyPattern(/\[\s*at\s*\]|\(\s*at\s*\)|\[\s*@\s*\]|\(\s*@\s*\)/gi, cur, '@');
  cur = applyPattern(/\[\s*:\s*\/\s*\/\s*\]/g, cur, '://');
  cur = applyPattern(/\[\s*:\s*\]/g, cur, ':');

  // 3. NFKC per character, so a compatibility form folds to ASCII WITHOUT
  //    changing the offset of any neighbouring character.
  const nfkcText: string[] = [];
  const nfkcMap: number[] = [];
  for (let i = 0; i < cur.text.length; i += 1) {
    const ch = cur.text[i]!;
    const folded = ch.normalize('NFKC');
    for (const outCh of folded.length > 0 ? folded : ch) {
      nfkcText.push(outCh);
      nfkcMap.push(cur.map[i]!);
    }
  }
  cur = { text: nfkcText.join(''), map: nfkcMap };

  // 4. Remove invisible / zero-width / bidi control characters, counting them
  //    so the EVADE-ZEROWIDTH rule has something to work with.
  const invisibles = /[\u200B-\u200F\u2060\uFEFF\u00AD\u202A-\u202E\u2066-\u2069]/g;
  let zeroWidth = 0;
  cur = applyPattern(invisibles, cur, () => {
    zeroWidth += 1;
    return '';
  });
  // 5. Collapse whitespace runs (incl. newlines) to a single space so that a
  //    phrase split across a soft line break still matches.
  cur = applyPattern(/[ \t\r\n\u00a0]+/g, cur, ' ');

  return { mapped: cur, zeroWidth };
}

/**
 * Fold word-internal homoglyphs to their ASCII skeleton, for MATCHING ONLY.
 * Only single-character confusables are applied here, so the folded string
 * keeps the SAME LENGTH as the normalised text and offsets stay valid. (The
 * multi-character tricks like rn->m belong to the URL domain-name analyser.)
 */
function foldHomoglyphs(text: string): { folded: string; changed: boolean } {
  const out: string[] = [];
  let changed = false;
  for (const ch of text) {
    const replacement = confusablesSingle[ch];
    if (replacement !== undefined) {
      out.push(replacement);
      // Only call it a homoglyph substitution when a NON-ASCII char became ASCII.
      if (ch.charCodeAt(0) > 0x7f) changed = true;
    } else {
      out.push(ch);
    }
  }
  return { folded: out.join(''), changed };
}

/**
 * Normalise raw text into a matching string plus a map back to the original.
 */
export function normalise(original: string): NormalisedText {
  const { mapped, zeroWidth } = normaliseChain(original);
  const text = mapped.text;
  const lower = text.toLowerCase();
  const { folded, changed } = foldHomoglyphs(text);
  return {
    text,
    lower,
    match: folded.toLowerCase(),
    offsetMap: mapped.map,
    zeroWidthCount: zeroWidth,
    homoglyphFolded: changed,
    original
  };
}

/** Use the offset map to turn a [start,end) span in `text` into the original span. */
export function toOriginalSpan(map: number[], start: number, end: number): { start: number; end: number } {
  const origStart = map[start] ?? 0;
  const lastIdx = end - 1 >= 0 ? end - 1 : start;
  const origEnd = (map[lastIdx] ?? origStart) + 1;
  return { start: origStart, end: Math.max(origEnd, origStart + 1) };
}
