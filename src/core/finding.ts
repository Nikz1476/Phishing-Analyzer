// Factory helpers so every Finding is built the same way, with severity
// always derived from weight and metadata always coming from one place.

import { STRUCTURAL_RULES, type RuleMeta } from './rules/catalogue';
import { severityFromWeight } from './severity';
import type { Evidence, Finding } from './types';

export function findingFromMeta(meta: RuleMeta, evidence: Evidence[], weightOverride?: number): Finding {
  const weight = weightOverride ?? meta.weight;
  return {
    id: meta.id,
    category: meta.category,
    severity: severityFromWeight(weight),
    weight,
    title: meta.title,
    evidence,
    why: meta.why,
    advice: meta.advice,
    mitre: meta.mitre,
    confidence: meta.confidence
  };
}

/** Build a finding for a structural rule id from the catalogue. */
export function structuralFinding(id: string, evidence: Evidence[], weightOverride?: number): Finding {
  const meta = STRUCTURAL_RULES[id];
  if (!meta) {
    // Defensive: a missing catalogue entry is a bug, but we never throw in the
    // engine - surface it as an info finding so it shows up in tests instead.
    return {
      id,
      category: 'technique',
      severity: 'info',
      weight: 0,
      title: `Unknown rule ${id}`,
      evidence,
      why: 'Internal: this rule has no catalogue entry.',
      advice: 'Report this as a bug.',
      mitre: [],
      confidence: 'low'
    };
  }
  return findingFromMeta(meta, evidence, weightOverride);
}