// The Learn page. Generated from the SAME metadata the engine uses, so the
// documentation can never drift from the actual rules (decision 003).

import { phraseRules } from '../core/data';
import { STRUCTURAL_RULES } from '../core/rules/catalogue';
import { weights } from '../core/data';
import type { RuleMeta } from '../core/rules/catalogue';
import { el } from './render';

interface LearnEntry {
  id: string;
  category: string;
  weight: number;
  title: string;
  why: string;
  advice: string;
  mitre: string[];
  confidence?: string | undefined;
  examples?: string[] | undefined;
  falsePositives?: string[] | undefined;
  source: 'phrase' | 'structural';
}

export function allLearnEntries(): LearnEntry[] {
  const out: LearnEntry[] = [];
  for (const r of phraseRules) {
    out.push({
      id: r.id, category: r.category, weight: r.weight, title: r.title,
      why: r.why, advice: r.advice, mitre: r.mitre, confidence: r.confidence,
      examples: r.examples, falsePositives: r.falsePositives, source: 'phrase'
    });
  }
  for (const m of Object.values(STRUCTURAL_RULES) as RuleMeta[]) {
    out.push({ ...m, source: 'structural' });
  }
  return out.sort((a, b) => a.category.localeCompare(b.category) || b.weight - a.weight);
}

export function renderLearn(container: HTMLElement): void {
  container.replaceChildren();

  container.appendChild(el('header', { class: 'panel' }, [
    el('h2', { text: 'Learn: every rule the engine can fire' }),
    el('p', { class: 'muted', text:
      `This page is generated from the same metadata that drives the engine - ${weights.version}, caps calibrated heuristically (hash ${weights.calibrationHash}). Each entry shows why the signal matters, what to do about it, and where it maps in MITRE ATT&CK. Phrase rules live in JSON under src/data/rules/; structural rules are code but declare the same fields.` })
  ]));

  const categories = new Set(allLearnEntries().map((e) => e.category));
  for (const category of [...categories].sort()) {
    const entries = allLearnEntries().filter((e) => e.category === category);
    const cap = weights.caps[category as keyof typeof weights.caps] ?? 0;
    container.appendChild(el('section', { class: 'panel' }, [
      el('h3', { text: `${category} (cap ${cap})` })
    ]));
    const last = container.lastElementChild as HTMLElement;

    for (const entry of entries) {
      const card = el('article', { class: 'learn-card', 'data-rule': entry.id });
      card.appendChild(el('header', {}, [
        el('code', { class: 'rule-id', text: entry.id }),
        el('span', { class: 'weight', text: `${entry.weight} pts` }),
        el('span', { class: 'source', text: entry.source }),
        el('h4', { text: entry.title })
      ]));
      card.appendChild(el('p', { text: entry.why }));
      card.appendChild(el('p', { class: 'advice', text: `What to do: ${entry.advice}` }));

      if (entry.examples && entry.examples.length > 0) {
        const ex = el('div', { class: 'examples' }, [el('span', { class: 'label', text: 'Examples' })]);
        for (const e of entry.examples) ex.appendChild(el('code', { text: e }));
        card.appendChild(ex);
      }
      if (entry.falsePositives && entry.falsePositives.length > 0) {
        const fp = el('div', { class: 'falsepos' }, [el('span', { class: 'label', text: 'False positives' })]);
        for (const e of entry.falsePositives) fp.appendChild(el('p', { text: e }));
        card.appendChild(fp);
      }

      const footer = el('footer', {});
      if (entry.confidence) footer.appendChild(el('span', { class: 'confidence', text: `confidence: ${entry.confidence}` }));
      for (const t of entry.mitre) footer.appendChild(el('span', { class: 'mitre', text: t }));
      card.appendChild(footer);
      last.appendChild(card);
    }
  }
}
