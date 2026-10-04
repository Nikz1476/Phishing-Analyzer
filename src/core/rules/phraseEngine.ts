// The phrase-rule engine: turns JSON rule packs into findings.
//
// WHY an interpreter rather than compiled code: one source of truth drives
// both the matches AND the Learn page (decision 003). The engine supports four
// pattern types and one cross-cutting idea - negation - which matters most for
// legitimate security notices ("we will never ask for your password").

import { phraseRules, type PhraseRule, type RulePattern } from '../data';
import { severityFromWeight } from '../severity';
import { tokenise } from '../normalise/tokenise';
import { toOriginalSpan } from '../normalise/text';
import type { Evidence, Finding, NormalisedText, Token } from '../types';

export interface RuleContext {
  flags: Set<string>; // 'has-url', 'has-attachment', ...
}

const NEGATION_WINDOW = 6;

function matchPhrase(tokens: Token[], phrase: string): number[] {
  const target = phrase.toLowerCase().split(/\s+/).filter(Boolean);
  if (target.length === 0) return [];
  const hits: number[] = [];
  for (let i = 0; i + target.length <= tokens.length; i += 1) {
    let ok = true;
    for (let j = 0; j < target.length; j += 1) {
      if (tokens[i + j]!.lower !== target[j]) {
        ok = false;
        break;
      }
    }
    if (ok) hits.push(i);
  }
  return hits;
}

function matchAnyOf(tokens: Token[], values: string[]): number[] {
  const hits: number[] = [];
  for (const value of values) hits.push(...matchPhrase(tokens, value));
  return hits;
}

function matchProximity(tokens: Token[], a: string[], b: string[], distance: number): number[] {
  const setA = new Set(a.map((s) => s.toLowerCase()));
  const setB = new Set(b.map((s) => s.toLowerCase()));
  const hits: number[] = [];
  for (let i = 0; i < tokens.length; i += 1) {
    if (!setA.has(tokens[i]!.lower)) continue;
    for (let j = Math.max(0, i - distance); j < Math.min(tokens.length, i + distance + 1); j += 1) {
      if (setB.has(tokens[j]!.lower)) {
        hits.push(Math.min(i, j));
        break;
      }
    }
  }
  return hits;
}
interface RegexHit {
  start: number; // normalised-text offsets
  end: number;
  nearbyOk: boolean;
}

function matchRegex(normalised: NormalisedText, pattern: RulePattern): RegexHit[] {
  if (!pattern.value) return [];
  let re: RegExp;
  try {
    re = new RegExp(pattern.value, pattern.flags ?? 'i');
  } catch {
    return [];
  }
  const source = normalised.match; // match the folded/lowered text
  re.lastIndex = 0;
  const hits: RegexHit[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(source)) !== null) {
    const start = m.index;
    const end = start + m[0].length;
    let nearbyOk = true;
    if (pattern.nearby && pattern.nearby.length > 0) {
      const windowStart = Math.max(0, start - (pattern.distance ?? 20));
      const windowEnd = Math.min(source.length, end + (pattern.distance ?? 20));
      const window = source.slice(windowStart, windowEnd);
      nearbyOk = pattern.nearby.some((w) => window.includes(w.toLowerCase()));
    }
    hits.push({ start, end, nearbyOk });
    if (m[0].length === 0) re.lastIndex += 1;
  }
  return hits;
}

/**
 * Does a negation phrase sit within NEGATION_WINDOW tokens BEFORE this match?
 * If so the match is suppressed (it is a legitimate "we will never ask...").
 */
function isNegated(tokens: Token[], matchTokenIndex: number, negations: string[]): boolean {
  for (const negation of negations) {
    const words = negation.toLowerCase().split(/\s+/).filter(Boolean);
    if (words.length === 0) continue;
    for (let start = Math.max(0, matchTokenIndex - NEGATION_WINDOW - words.length + 1); start <= matchTokenIndex; start += 1) {
      let ok = true;
      for (let k = 0; k < words.length; k += 1) {
        if (start + k >= tokens.length || tokens[start + k]!.lower !== words[k]) {
          ok = false;
          break;
        }
      }
      if (ok) return true;
    }
  }
  return false;
}

function tokenIndexOf(tokens: Token[], charOffset: number): number {
  for (let i = 0; i < tokens.length; i += 1) {
    if (tokens[i]!.start >= charOffset) return i;
  }
  return tokens.length - 1;
}
/** Run one phrase rule against the normalised text, returning a finding or null. */
export function runPhraseRule(
  rule: PhraseRule,
  normalised: NormalisedText,
  tokens: Token[],
  context: RuleContext
): Finding | null {
  if (rule.requiresAny && rule.requiresAny.length > 0) {
    if (!rule.requiresAny.some((flag) => context.flags.has(flag))) return null;
  }

  const hits: Array<{ start: number; end: number; tokenIndex: number }> = [];

  for (const pattern of rule.patterns) {
    if (pattern.type === 'phrase' && pattern.value) {
      const wordCount = pattern.value.split(/\s+/).filter(Boolean).length;
      for (const idx of matchPhrase(tokens, pattern.value)) {
        hits.push({ start: tokens[idx]!.start, end: tokens[idx + wordCount - 1]?.end ?? tokens[idx]!.end, tokenIndex: idx });
      }
    } else if (pattern.type === 'anyOf' && pattern.values) {
      const longest = pattern.values.map((v) => v.split(/\s+/).filter(Boolean).length).reduce((a, b) => Math.max(a, b), 1);
      for (const idx of matchAnyOf(tokens, pattern.values)) {
        hits.push({ start: tokens[idx]!.start, end: tokens[idx + longest - 1]?.end ?? tokens[idx]!.end, tokenIndex: idx });
      }
    } else if (pattern.type === 'proximity' && pattern.a && pattern.b) {
      for (const idx of matchProximity(tokens, pattern.a, pattern.b, pattern.distance ?? 6)) {
        hits.push({ start: tokens[idx]!.start, end: tokens[idx]!.end, tokenIndex: idx });
      }
    } else if (pattern.type === 'regex') {
      for (const hit of matchRegex(normalised, pattern)) {
        if (!hit.nearbyOk) continue;
        hits.push({ start: hit.start, end: hit.end, tokenIndex: tokenIndexOf(tokens, hit.start) });
      }
    }
  }

  // Negation suppression.
  const negations = rule.negations ?? [];
  const surviving = negations.length > 0 ? hits.filter((h) => !isNegated(tokens, h.tokenIndex, negations)) : hits;
  if (surviving.length === 0) return null;

  // Distinct occurrences: dedupe by the matched snippet text.
  const distinct = new Map<string, { start: number; end: number }>();
  for (const h of surviving) {
    const span = toOriginalSpan(normalised.offsetMap, h.start, h.end);
    const snippet = normalised.original.slice(span.start, span.end);
    const key = snippet.trim().toLowerCase();
    if (!distinct.has(key)) distinct.set(key, span);
  }

  const evidence: Evidence[] = [...distinct.entries()].slice(0, 8).map(([snippet, span]) => ({
    source: 'body',
    snippet,
    start: span.start,
    end: span.end
  }));

  return {
    id: rule.id,
    category: rule.category,
    severity: severityFromWeight(rule.weight),
    weight: rule.weight,
    title: rule.title,
    evidence,
    why: rule.why,
    advice: rule.advice,
    mitre: rule.mitre,
    confidence: rule.confidence
  };
}

/** Run every phrase rule, returning all findings (order independent). */
export function runPhraseRules(normalised: NormalisedText, context: RuleContext): Finding[] {
  const tokens = tokenise(normalised);
  const findings: Finding[] = [];
  for (const rule of phraseRules) {
    const finding = runPhraseRule(rule, normalised, tokens, context);
    if (finding) findings.push(finding);
  }
  return findings;
}