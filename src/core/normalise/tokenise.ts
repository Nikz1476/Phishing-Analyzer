// Tokeniser for the phrase engine.
//
// WHY a hand-written tokeniser rather than a split on spaces: we need each
// token's position (in the normalised text) so proximity rules and negation
// windows can measure distance in TOKENS, and so evidence can map back to the
// original. We keep the original spelling (via `value`) and a lowercased copy
// for case-insensitive matching.

import { toOriginalSpan } from './text';
import type { NormalisedText, Token } from '../types';

/** A token is a run of word characters (letters, digits, _) or a single symbol. */
const TOKEN_RE = /[\p{L}\p{N}_]+|[\p{S}\p{P}]/gu;

export function tokenise(normalised: NormalisedText): Token[] {
  const tokens: Token[] = [];
  const { text, offsetMap } = normalised;
  TOKEN_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = TOKEN_RE.exec(text)) !== null) {
    const start = m.index;
    const end = start + m[0].length;
    const span = toOriginalSpan(offsetMap, start, end);
    tokens.push({
      value: m[0],
      lower: m[0].toLowerCase(),
      start,
      end,
      origStart: span.start,
      origEnd: span.end
    });
  }
  return tokens;
}

/** Convert a [start,end) token-index range back to an original-text span. */
export function tokenRangeToOriginal(
  normalised: NormalisedText,
  tokens: Token[],
  startToken: number,
  endToken: number
): { start: number; end: number } {
  const first = tokens[startToken];
  const last = tokens[endToken];
  if (!first || !last) return { start: 0, end: 0 };
  return toOriginalSpan(normalised.offsetMap, first.start, last.end);
}
