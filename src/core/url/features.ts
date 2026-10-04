// Low-level string features used by the URL rules: script detection,
// confusable skeletons, edit distance and entropy.

import { confusablesMulti, confusablesSingle } from '../data';

/** Which Unicode scripts appear in a label. Empty means scripts-unknown/ASCII-only. */
export function scriptsInLabel(label: string, hostUnicode?: string): Set<string> {
  const scripts = new Set<string>();
  const source = hostUnicode ?? label;
  for (const ch of source) {
    if (ch.codePointAt(0)! < 0x80) {
      // ASCII: count as Latin so 'paypal' + Cyrillic reads as mixed.
      scripts.add('Latin');
      continue;
    }
    const script = scriptOf(ch);
    if (script) scripts.add(script);
  }
  return scripts;
}

const SCRIPT_TESTS: Array<[string, RegExp]> = [
  ['Latin', /\p{Script=Latin}/u],
  ['Cyrillic', /\p{Script=Cyrillic}/u],
  ['Greek', /\p{Script=Greek}/u],
  ['Hebrew', /\p{Script=Hebrew}/u],
  ['Arabic', /\p{Script=Arabic}/u],
  ['Han', /\p{Script=Han}/u],
  ['Hiragana', /\p{Script=Hiragana}/u],
  ['Katakana', /\p{Script=Katakana}/u],
  ['Hangul', /\p{Script=Hangul}/u],
  ['Devanagari', /\p{Script=Devanagari}/u],
  ['Thai', /\p{Script=Thai}/u],
  ['Armenian', /\p{Script=Armenian}/u],
  ['Georgian', /\p{Script=Georgian}/u]
];

function scriptOf(ch: string): string | null {
  for (const [name, re] of SCRIPT_TESTS) {
    if (re.test(ch)) return name;
  }
  return null;
}

/** True when a label mixes scripts (e.g. Latin + Cyrillic in one label). */
export function isMixedScript(label: string, unicodeLabel: string): boolean {
  const scripts = scriptsInLabel(label, unicodeLabel);
  return scripts.size > 1;
}

/**
 * Fold a string to an attacker-friendly ASCII skeleton using the confusables
 * table. Multi-character tricks (rn->m, vv->w) are applied too, because that
 * is how 'paypa1' / 'rnicrosoft' style fakes are built.
 */
export function skeletonFold(text: string): string {
  let out = text.toLowerCase();
  // Multi-char first (order matters: 'rn' before single-char passes).
  for (const [from, to] of Object.entries(confusablesMulti)) {
    out = out.split(from).join(to);
  }
  let result = '';
  for (const ch of out) {
    result += confusablesSingle[ch] ?? ch;
  }
  return result;
}

/** Optimal string alignment distance (Damerau-Levenshtein, restricted). */
export function damerauLevenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const d: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = 0; i <= m; i += 1) d[i]![0] = i;
  for (let j = 0; j <= n; j += 1) d[0]![j] = j;
  for (let i = 1; i <= m; i += 1) {
    for (let j = 1; j <= n; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i]![j] = Math.min(
        d[i - 1]![j]! + 1,
        d[i]![j - 1]! + 1,
        d[i - 1]![j - 1]! + cost
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i]![j] = Math.min(d[i]![j]!, d[i - 2]![j - 2]! + cost);
      }
    }
  }
  return d[m]![n]!;
}

/** Shannon entropy (bits per character) of a string. */
export function shannonEntropy(text: string): number {
  if (text.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of text) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / text.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}