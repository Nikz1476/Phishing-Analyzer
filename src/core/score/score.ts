// Scoring engine. Deterministic, additive, capped and reconcilable - never
// hidden terms and never ML in the shipped path (decision 004).
//
// INVARIANT (Section 9.6): the sum of the displayed contributions
// (categoryApplied + combos + mitigations) must EQUAL `raw` exactly, and
// score = clamp(round(raw)). Every branch below is written so that the
// breakdown rows sum to raw by construction.

import { weights } from '../data';
import type { Category, CategoryBreakdown, Classification, Combo, Finding, Mitigation } from '../types';

const CAPS = weights.caps;
const REPEAT_FACTOR = weights.repeatFactor;

/** LANG-URGENCY has a documented ceiling (first cue 6, +3 each, max 12). */
const RULE_POINT_CAPS: Record<string, number> = {
  'LANG-URGENCY': 12
};

/** Points contributed by a single finding, after repeat factor and cap. */
export function findingPoints(f: Finding): number {
  const occurrences = Math.max(1, f.occurrences ?? 1);
  let points = f.weight + (occurrences - 1) * f.weight * REPEAT_FACTOR;
  const cap = f.pointCap ?? RULE_POINT_CAPS[f.id];
  if (cap !== undefined) points = Math.min(points, cap);
  return points;
}

function weightOrder(severity: string): number {
  return { info: 1, low: 2, medium: 3, high: 4, critical: 5 }[severity] ?? 0;
}

/** Corroboration: independent signals that agree with each other. */
export function computeCombos(findings: Finding[]): Combo[] {
  const ids = new Set(findings.map((f) => f.id));
  const combos: Combo[] = [];

  const credHigh = findings.some((f) => f.category === 'credential' && weightOrder(f.severity) >= 4);
  const urlMedium = findings.some((f) => f.category === 'url' && weightOrder(f.severity) >= 3);
  if (credHigh && urlMedium) {
    combos.push({ id: 'CMB-CRED-LINK', bonus: weights.combos['CMB-CRED-LINK'] ?? 10, because: ['credential request', 'suspicious link'] });
  }

  const authOrUrlInfra = findings.some((f) =>
    ['HDR-SPF-FAIL', 'HDR-SPF-SOFTFAIL', 'HDR-DKIM-FAIL', 'HDR-DMARC-FAIL', 'HDR-AUTH-MISALIGNED',
      'URL-TYPOSQUAT', 'URL-COMBOSQUAT', 'URL-TEXT-MISMATCH'].includes(f.id)
  );
  if (ids.has('IMP-BRAND-MISMATCH') && authOrUrlInfra) {
    combos.push({ id: 'CMB-BRAND-INFRA', bonus: weights.combos['CMB-BRAND-INFRA'] ?? 10, because: ['brand claimed', 'infrastructure does not match'] });
  }

  const paymentPressure = ['FIN-BANK-CHANGE', 'FIN-PAYMENT-PRESSURE', 'FIN-GIFTCARD'].some((id) => ids.has(id));
  const pressureLang = findings.some((f) => f.id === 'LANG-URGENCY' || f.id === 'LANG-SECRECY' || f.id.startsWith('HDR-REPLYTO-'));
  if (paymentPressure && pressureLang) {
    combos.push({ id: 'CMB-PAYMENT-PRESSURE', bonus: weights.combos['CMB-PAYMENT-PRESSURE'] ?? 12, because: ['payment pressure', 'urgency or secrecy'] });
  }

  const deliveryVector = ['ATT-EXECUTABLE', 'ATT-MACRO-FILE', 'ATT-HTML-SMUGGLING', 'ATT-ARCHIVE-PASSWORD', 'ATT-DISK-IMAGE', 'TECH-CLICKFIX'].some((id) => ids.has(id));
  const pretext = ['FIN-INVOICE-UNEXPECTED', 'LANG-URGENCY'].some((id) => ids.has(id)) || [...ids].some((id) => id.startsWith('IMP-'));
  if (deliveryVector && pretext) {
    combos.push({ id: 'CMB-EXEC-LURE', bonus: weights.combos['CMB-EXEC-LURE'] ?? 10, because: ['delivery vector', 'familiar pretext'] });
  }

  return combos;
}

function hasCritical(findings: Finding[]): boolean {
  return findings.some((f) => f.severity === 'critical');
}

export interface ScoreInput {
  findings: Finding[];
  mitigations: Mitigation[];
}

export interface ScoreOutput {
  score: number;
  classification: Classification;
  breakdown: CategoryBreakdown[];
  combos: Combo[];
  mitigations: Mitigation[];
  raw: number;
}

export function score(input: ScoreInput): ScoreOutput {
  const findings = input.findings.filter((f) => !f.mitigation);
  const criticalExists = hasCritical(findings);

  // ---- 1. Repeat factor + per-URL cap -------------------------------------
  const pointsByFinding = new Map<Finding, number>();
  const perUrl = new Map<string, number>();
  for (const f of findings) {
    const pts = findingPoints(f);
    pointsByFinding.set(f, pts);
    if (f.groupId) {
      const current = perUrl.get(f.groupId) ?? 0;
      const allowed = Math.max(0, weights.perUrlCap - current);
      const applied = Math.min(pts, allowed);
      perUrl.set(f.groupId, current + applied);
      pointsByFinding.set(f, applied);
    }
  }

  // ---- 2. Category caps ---------------------------------------------------
  const breakdown: CategoryBreakdown[] = [];
  const categories = Object.keys(CAPS) as Category[];
  for (const category of categories) {
    const raw = findings
      .filter((f) => f.category === category)
      .reduce((sum, f) => sum + (pointsByFinding.get(f) ?? 0), 0);
    const cap = CAPS[category];
    breakdown.push({ category, raw, cap, applied: Math.min(raw, cap) });
  }

  // ---- 3. Corroboration ---------------------------------------------------
  const combos = computeCombos(findings);
  const corroboration = Math.min(combos.reduce((s, c) => s + c.bonus, 0), weights.corroborationCap);

  // ---- 4. Mitigations -----------------------------------------------------
  let mitigation: Mitigation[] = [];
  if (!criticalExists && input.mitigations.length > 0) {
    const sum = input.mitigations.reduce((s, m) => s + m.delta, 0);
    const delta = Math.max(weights.mitigationFloor, sum);
    mitigation = [{
      id: input.mitigations.map((m) => m.id).join('+'),
      delta,
      because: input.mitigations.map((m) => m.because).join(' ')
    }];
  }
  const mitigationTotal = mitigation.reduce((s, m) => s + m.delta, 0);

  // ---- 5. Raw + score -----------------------------------------------------
  const categoryTotal = breakdown.reduce((s, b) => s + b.applied, 0);
  const raw = categoryTotal + corroboration + mitigationTotal;
  const scoreValue = Math.max(0, Math.min(100, Math.round(raw)));

  // ---- 6. Classification (with floors) ------------------------------------
  const criticalCategories = new Set(findings.filter((f) => f.severity === 'critical').map((f) => f.category));
  const suspiciousMin = weights.classificationThresholds.suspicious;
  const highMin = weights.classificationThresholds.highRisk;
  let classification: Classification =
    scoreValue >= highMin ? 'High Risk' : scoreValue >= suspiciousMin ? 'Suspicious' : 'Low Risk';

  if (criticalExists && classification === 'Low Risk') classification = 'Suspicious';
  if (criticalCategories.size >= 2) classification = 'High Risk';

  return { score: scoreValue, classification, breakdown, combos, mitigations: mitigation, raw };
}
