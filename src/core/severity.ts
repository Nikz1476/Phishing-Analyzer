import { weights } from './data';
import type { Severity } from './types';

/**
 * Severity is DERIVED from weight, never hand-set per finding. WHY: it keeps
 * the UI chips and the scoring table in lockstep - change a weight and the
 * severity follows, so nothing can drift out of sync.
 */
export function severityFromWeight(weight: number): Severity {
  const t = weights.severityThresholds;
  if (weight <= t.info) return 'info';
  if (weight < t.medium) return 'low';
  if (weight < t.high) return 'medium';
  if (weight < t.critical) return 'high';
  return 'critical';
}

/** Human-readable order for sorting findings by importance. */
export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};