// Typed access to the JSON data files. WHY a single module: it gives the rest
// of the engine one import surface and one place where missing/!malformed
// data would surface, rather than scattering `import x from '...json'`
// everywhere. JSON is bundled at build time (resolveJsonModule), so there is
// no runtime fetch and nothing to go wrong in the browser.

import brandsJson from '../data/brands.json';
import confusablesJson from '../data/confusables.json';
import freemailJson from '../data/freemail.json';
import platformsJson from '../data/platforms.json';
import pslJson from '../data/psl-subset.json';
import riskyTldsJson from '../data/risky-tlds.json';
import shortenersJson from '../data/shorteners.json';
import weightsJson from '../data/weights.json';

import languageRules from '../data/rules/language.json';
import credentialRules from '../data/rules/credential.json';
import financialRules from '../data/rules/financial.json';
import impersonationRules from '../data/rules/impersonation.json';
import techniqueRules from '../data/rules/techniques.json';

import type { Category, Confidence } from './types';

export interface BrandEntry {
  aliases: string[];
  legitDomains: string[];
  labels: string[];
}

export interface RulePattern {
  type: 'phrase' | 'regex' | 'proximity' | 'anyOf';
  value?: string;
  values?: string[];
  a?: string[];
  b?: string[];
  distance?: number;
  flags?: string;
  nearby?: string[];
}

export interface PhraseRule {
  id: string;
  category: Category;
  weight: number;
  title: string;
  why: string;
  advice: string;
  mitre: string[];
  confidence: Confidence;
  requiresAny?: string[];
  patterns: RulePattern[];
  negations?: string[];
  examples?: string[];
  falsePositives?: string[];
}

export interface Weights {
  version: string;
  calibrationHash: string;
  caps: Record<Category, number>;
  perUrlCap: number;
  repeatFactor: number;
  corroborationCap: number;
  mitigationFloor: number;
  severityThresholds: { info: number; low: number; medium: number; high: number; critical: number };
  classificationThresholds: { suspicious: number; highRisk: number };
  combos: Record<string, number>;
  mitigations: Record<string, number>;
}

// `_comment` keys exist for humans reading the JSON; they are metadata, not
// data, so we strip them here once rather than guarding at every call site.
function withoutCommentKeys<T>(obj: Record<string, unknown>): Record<string, T> {
  const out: Record<string, T> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (k.startsWith('_')) continue;
    out[k] = v as T;
  }
  return out;
}

export const brands: Record<string, BrandEntry> =
  withoutCommentKeys<BrandEntry>(brandsJson as unknown as Record<string, unknown>);

export const shortenerDomains: string[] = shortenersJson.domains;
export const freemailDomains: string[] = freemailJson.domains;
export const riskyTlds: string[] = riskyTldsJson.tlds;
export const platformDomains: string[] = platformsJson.domains;
export const multiLabelSuffixes: string[] = pslJson._multiLabel;
export const singleLabelSuffixes: Set<string> = new Set(pslJson._singleLabel);
export const confusablesSingle: Record<string, string> = confusablesJson.singleChar;
export const confusablesMulti: Record<string, string> = confusablesJson.multiChar;
export const weights: Weights = weightsJson as unknown as Weights;

/** Every phrase/pattern rule, in a stable order (determinism matters). */
export const phraseRules: PhraseRule[] = [
  ...(languageRules.rules as PhraseRule[]),
  ...(credentialRules.rules as PhraseRule[]),
  ...(financialRules.rules as PhraseRule[]),
  ...(impersonationRules.rules as PhraseRule[]),
  ...(techniqueRules.rules as PhraseRule[])
].sort((a, b) => a.id.localeCompare(b.id));

/** All brands flattened to a lookup of legitimate domain -> brand key. */
export const legitDomainToBrand = new Map<string, string>();
for (const [key, entry] of Object.entries(brands)) {
  for (const dom of entry.legitDomains) {
    legitDomainToBrand.set(dom.toLowerCase(), key);
  }
}
