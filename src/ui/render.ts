// Result rendering. Two hard rules from Section 3 are enforced by construction:
//   1. NEVER innerHTML with user-derived text - everything below uses
//      createElement + textContent, so hostile input is inert by default.
//   2. URLs are shown as defanged plain text only, never as <a href>.

import { defang } from '../core/url/defang';
import type { AnalysisResult, Finding } from '../core/types';

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Record<string, string | number | boolean | undefined> = {},
  children: (Node | string)[] = []
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === false) continue;
    if (key === 'text') node.textContent = String(value);
    else if (key === 'class') node.className = String(value);
    else if (value === true) node.setAttribute(key, '');
    else node.setAttribute(key, String(value));
  }
  for (const child of children) {
    node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

const SAFETY_STATEMENTS = [
  'This is an educational triage tool that highlights common warning signs. It cannot determine whether an email is malicious or safe.',
  'Do not click links or open attachments to “test” them.',
  'Verify important messages independently, using the organisation’s official website, app or a contact method you already trust, not details taken from the email.',
  'Everything is analysed in your browser. Nothing you paste is uploaded or stored.'
];

export function safetyBanner(): HTMLElement {
  return el('aside', { class: 'safety-banner', role: 'note' }, [
    el('strong', { text: 'Before you use this result:' }),
    el('ul', {}, SAFETY_STATEMENTS.map((s) => el('li', { text: s })))
  ]);
}

function scoreGauge(result: AnalysisResult): HTMLElement {
  const band = result.classification;
  const colour =
    band === 'High Risk' ? 'var(--danger)' : band === 'Suspicious' ? 'var(--warn)' : 'var(--ok)';
  const degrees = Math.round((result.score / 100) * 360);

  const wrap = el('div', { class: 'gauge-wrap' });
  const gauge = el('div', { class: 'gauge', role: 'img', 'aria-label': `Score ${result.score} out of 100` });
  // Conic ring; colour is decorative - the number + text label carry meaning.
  gauge.style.setProperty('--deg', `${degrees}deg`);
  gauge.style.setProperty('--gauge-colour', colour);
  gauge.appendChild(el('span', { class: 'gauge-value', text: String(result.score) }));
  gauge.appendChild(el('span', { class: 'gauge-denom', text: 'of 100' }));

  const meta = el('div', { class: 'gauge-meta' }, [
    el('div', { class: `chip chip-${band.replace(/\s+/g, '-').toLowerCase()}`, text: band }),
    el('div', { class: 'coverage', text: `Coverage level ${result.coverage.level} of 4` }),
    el('p', { class: 'score-caption', text: captionFor(result) })
  ]);

  wrap.appendChild(gauge);
  wrap.appendChild(meta);
  return wrap;
}

function captionFor(result: AnalysisResult): string {
  if (result.classification === 'Low Risk') return 'Few warning signs were found.';
  if (result.classification === 'Suspicious') return 'Several warning signs were found - treat with care.';
  return 'Many warning signs were found - do not act on this message.';
}

function breakdownTable(result: AnalysisResult): HTMLElement {
  const table = el('table', { class: 'breakdown' });
  const head = el('tr', {}, [
    el('th', { text: 'Category' }), el('th', { text: 'Raw' }), el('th', { text: 'Cap' }), el('th', { text: 'Applied' })
  ]);
  table.appendChild(el('thead', {}, [head]));

  const body = el('tbody');
  let appliedTotal = 0;
  for (const row of result.breakdown) {
    appliedTotal += row.applied;
    body.appendChild(el('tr', { class: row.applied === 0 ? 'zero' : '' }, [
      el('td', { text: row.category }),
      el('td', { text: row.raw.toFixed(2) }),
      el('td', { text: row.cap }),
      el('td', { text: row.applied.toFixed(2) })
    ]));
  }
  for (const combo of result.combos) {
    appliedTotal += combo.bonus;
    body.appendChild(el('tr', { class: 'bonus' }, [
      el('td', { text: `Corroboration: ${combo.id}` }),
      el('td', { text: combo.bonus }), el('td', { text: '-' }), el('td', { text: `+${combo.bonus}` })
    ]));
  }
  for (const m of result.mitigations) {
    appliedTotal += m.delta;
    body.appendChild(el('tr', { class: 'mitigation' }, [
      el('td', { text: `Mitigation: ${m.id}` }),
      el('td', { text: m.delta }), el('td', { text: '-' }), el('td', { text: String(m.delta) })
    ]));
  }
  table.appendChild(body);

  const rounded = Math.round(appliedTotal);
  table.appendChild(el('tfoot', {}, [
    el('tr', { class: 'total' }, [
      el('td', { text: `Total (rounds to score ${result.score})` }),
      el('td', { text: appliedTotal.toFixed(2) }),
      el('td', { text: '' }),
      el('td', { text: String(rounded) })
    ])
  ]));
  return table;
}

function findingCard(f: Finding, points: number): HTMLElement {
  const card = el('article', { class: 'finding', 'data-rule': f.id });
  card.appendChild(el('header', {}, [
    el('span', { class: `sev sev-${f.severity}`, text: f.severity }),
    el('span', { class: 'finding-id', text: f.id }),
    el('span', { class: 'finding-points', text: `${points} pts` }),
    el('h4', { text: f.title })
  ]));

  if (f.evidence.length > 0) {
    const ev = el('div', { class: 'evidence' }, [
      el('span', { class: 'evidence-label', text: 'Evidence' })
    ]);
    for (const e of f.evidence.slice(0, 6)) {
      ev.appendChild(el('code', {
        text: `${e.label ? `[${e.label}] ` : ''}${defang(e.snippet)}`
      }));
    }
    card.appendChild(ev);
  }

  card.appendChild(el('p', { class: 'why', text: f.why }));
  card.appendChild(el('p', { class: 'advice', text: `What to do: ${f.advice}` }));

  const footer = el('footer', {}, [
    el('span', { class: 'confidence', text: `confidence: ${f.confidence}` })
  ]);
  for (const t of f.mitre) {
    // Plain text chips, never links - Section 10 requires link text only.
    footer.appendChild(el('span', { class: 'mitre', text: t }));
  }
  card.appendChild(footer);
  return card;
}

function findingsSection(result: AnalysisResult): HTMLElement {
  const section = el('section', { class: 'panel' }, [el('h3', { text: 'Warning signs' })]);
  if (result.findings.length === 0) {
    section.appendChild(el('p', { text: 'No rule fired. That does not mean the message is safe - see what was not checked below.' }));
    return section;
  }

  const pointsById = new Map<string, number>();
  for (const f of result.findings) {
    const occ = Math.max(1, f.occurrences ?? 1);
    pointsById.set(f.id, (pointsById.get(f.id) ?? 0) + f.weight * (1 + (occ - 1) * 0.25));
  }

  const sorted = [...result.findings].sort((a, b) => (pointsById.get(b.id) ?? 0) - (pointsById.get(a.id) ?? 0));
  const list = el('div', { class: 'findings' });
  const rendered = new Set<string>();
  for (const f of sorted) {
    if (rendered.has(f.id)) continue;
    rendered.add(f.id);
    list.appendChild(findingCard(f, Math.round(pointsById.get(f.id) ?? 0)));
  }
  section.appendChild(list);
  return section;
}

function coveragePanel(result: AnalysisResult): HTMLElement {
  const panel = el('section', { class: 'panel coverage-panel' }, [
    el('h3', { text: 'What was checked' })
  ]);
  panel.appendChild(el('p', { text: `Coverage level ${result.coverage.level} of 4.` }));

  const checked = el('ul', { class: 'checked' },
    result.coverage.checked.map((c) => el('li', { text: c })));
  panel.appendChild(el('h4', { text: 'Checked' }));
  panel.appendChild(checked);

  panel.appendChild(el('h4', { text: 'Not checked' }));
  panel.appendChild(el('ul', { class: 'not-checked' },
    result.coverage.notChecked.map((c) => el('li', { text: c }))));

  if (result.mitigations.length > 0) {
    panel.appendChild(el('p', { class: 'caveat', text: 'Passing authentication does not prove an email is safe.' }));
  }
  return panel;
}

/** Original text with evidence spans highlighted (built from the offset map). */
function annotatedSource(result: AnalysisResult): HTMLElement {
  const wrap = el('pre', { class: 'annotated', 'data-testid': 'annotated-source' });
  const spans: Array<{ start: number; end: number; rule: string }> = [];
  for (const f of result.findings) {
    for (const e of f.evidence) {
      if (e.start === undefined || e.end === undefined || e.end <= e.start) continue;
      if (e.end > result.original.length) continue;
      spans.push({ start: e.start, end: e.end, rule: f.id });
    }
  }
  spans.sort((a, b) => a.start - b.start);

  const text = result.original;
  let cursor = 0;
  for (const span of spans) {
    if (span.start < cursor) continue; // overlapping spans are skipped, not nested
    if (span.start > cursor) wrap.appendChild(document.createTextNode(text.slice(cursor, span.start)));
    const mark = el('mark', { title: span.rule, text: text.slice(span.start, span.end) });
    wrap.appendChild(mark);
    cursor = span.end;
  }
  if (cursor < text.length) wrap.appendChild(document.createTextNode(text.slice(cursor)));
  return wrap;
}

function headerView(result: AnalysisResult): HTMLElement {
  const h = result.headerReport;
  const panel = el('div', { class: 'header-view' });
  if (!h) {
    panel.appendChild(el('p', { text: 'No raw headers were supplied. Paste the full original message (including headers) for header forensics.' }));
    return panel;
  }

  const table = el('table', { class: 'kv' });
  const rows: Array<[string, string]> = [
    ['From', h.from ?? '—'],
    ['Reply-To', h.replyTo ?? '—'],
    ['Return-Path', h.returnPath ?? '—'],
    ['Message-ID', h.messageId ?? '—'],
    ['Subject', h.subject ?? '—'],
    ['Date', h.date ?? '—']
  ];
  for (const [k, v] of rows) {
    table.appendChild(el('tr', {}, [el('th', { text: k }), el('td', { text: v })]));
  }
  panel.appendChild(table);

  panel.appendChild(el('h4', { text: 'Authentication results (as reported) + local alignment' }));
  if (h.authResults.length === 0) {
    panel.appendChild(el('p', { text: 'No Authentication-Results header. This tool reads what the receiving server reported; it does not verify SPF/DKIM/DMARC itself (that would need DNS lookups, which would break the privacy rule).' }));
  } else {
    const auth = el('table', { class: 'kv' });
    auth.appendChild(el('tr', {}, [
      el('th', { text: 'Method' }), el('th', { text: 'Reported' }), el('th', { text: 'authserv-id (trusted)' })
    ]));
    for (const a of h.authResults) {
      auth.appendChild(el('tr', {}, [
        el('td', { text: a.method }),
        el('td', { text: a.result }),
        el('td', { text: `${a.authservId}${a.trusted ? '' : '  (not trusted)'}` })
      ]));
    }
    panel.appendChild(auth);
    if (h.alignment) {
      panel.appendChild(el('p', { class: 'muted', text:
        `Local alignment: SPF ${String(h.alignment.spf.locallyAligned)}, DKIM ${String(h.alignment.dkim.locallyAligned)}, DMARC computed ${String(h.alignment.dmarc.locallyComputed)} (relaxed).` }));
    }
  }

  if (h.receivedHops.length > 0) {
    panel.appendChild(el('h4', { text: 'Received hop timeline (oldest first)' }));
    const hops = el('ol', { class: 'hops' });
    for (const hop of h.receivedHops) {
      const delay = hop.delayMs !== null ? `${Math.round(hop.delayMs / 1000)}s` : '—';
      hops.appendChild(el('li', {}, [
        el('span', { text: `${hop.from ?? '?'} → ${hop.by ?? '?'}` }),
        hop.ip ? el('code', { text: hop.ip }) : null,
        el('span', { class: 'muted', text: `delay ${delay}` }),
        ...hop.notes.map((n) => el('span', { class: 'warn', text: n }))
      ].filter(Boolean) as (Node | string)[]));
    }
    panel.appendChild(hops);
  }
  return panel;
}

function urlView(result: AnalysisResult): HTMLElement {
  const panel = el('div', { class: 'url-view' });
  if (result.urlReports.length === 0) {
    panel.appendChild(el('p', { text: 'No links were found in this message.' }));
    return panel;
  }
  for (const r of result.urlReports) {
    const card = el('article', { class: 'url-card' });
    card.appendChild(el('code', { class: 'defanged', text: r.defanged }));
    const meta = el('ul', { class: 'url-meta' }, [
      el('li', { text: `Registrable domain: ${r.registrableDomain || '—'}` }),
      el('li', { text: `Scheme: ${r.scheme || '—'}` }),
      el('li', { text: `Host: ${r.host || '—'}` })
    ]);
    if (r.unwrapChain.length > 1) {
      meta.appendChild(el('li', { class: 'warn', text: `Unwrap chain: ${r.unwrapChain.join('  →  ')}` }));
    }
    card.appendChild(meta);

    if (r.findings.length === 0) {
      card.appendChild(el('p', { class: 'muted', text: 'No URL rule fired for this link.' }));
    } else {
      const list = el('ul', { class: 'url-findings' });
      for (const f of r.findings) {
        list.appendChild(el('li', {}, [
          el('code', { text: f.id }),
          el('span', { text: ` — ${f.title}` }),
          el('span', { class: 'finding-points', text: `${f.weight} pts` })
        ]));
      }
      card.appendChild(list);
    }
    panel.appendChild(card);
  }
  return panel;
}

function iocPanel(result: AnalysisResult): HTMLElement {
  const panel = el('div', { class: 'ioc-panel' });
  const groups: Array<[string, string[]]> = [
    ['URLs', result.iocs.urls],
    ['Domains', result.iocs.domains],
    ['IPs', result.iocs.ips],
    ['Emails', result.iocs.emails]
  ];
  const copyTarget = el('div', { class: 'ioc-copy' });
  const textarea = el('textarea', { readonly: 'true', 'data-testid': 'ioc-json', rows: '4' });
  textarea.value = JSON.stringify(result.iocs, null, 2);
  copyTarget.appendChild(textarea);

  const copyBtn = el('button', { type: 'button', class: 'btn', text: 'Copy IOCs as JSON' });
  copyBtn.addEventListener('click', async () => {
    await navigator.clipboard.writeText(textarea.value);
    copyBtn.textContent = 'Copied';
    setTimeout(() => { copyBtn.textContent = 'Copy IOCs as JSON'; }, 1200);
  });
  copyTarget.appendChild(copyBtn);
  panel.appendChild(copyTarget);

  for (const [name, values] of groups) {
    panel.appendChild(el('h4', { text: name }));
    if (values.length === 0) {
      panel.appendChild(el('p', { class: 'muted', text: 'None found.' }));
      continue;
    }
    const ul = el('ul', { class: 'ioc-list' });
    for (const v of values) ul.appendChild(el('li', { text: defang(v) }));
    panel.appendChild(ul);
  }
  return panel;
}

function tabs(views: Array<{ id: string; label: string; node: HTMLElement }>): HTMLElement {
  const wrap = el('div', { class: 'tabs' });
  const bar = el('div', { class: 'tab-bar', role: 'tablist' });
  const paneHost = el('div', { class: 'tab-panes' });
  views.forEach((view, i) => {
    const pane = el('section', { class: 'tab-pane', role: 'tabpanel', id: `pane-${view.id}` });
    pane.appendChild(view.node);
    pane.hidden = i !== 0;
    paneHost.appendChild(pane);

    const btn = el('button', {
      type: 'button',
      class: `tab${i === 0 ? ' active' : ''}`,
      role: 'tab',
      'aria-selected': i === 0 ? 'true' : 'false',
      text: view.label
    });
    btn.addEventListener('click', () => {
      bar.querySelectorAll('.tab').forEach((b) => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      paneHost.querySelectorAll<HTMLElement>('.tab-pane').forEach((p) => { p.hidden = true; });
      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');
      pane.hidden = false;
    });
    bar.appendChild(btn);
  });
  wrap.appendChild(bar);
  wrap.appendChild(paneHost);
  return wrap;
}

/** Render the whole result into the container. */
export function renderResult(container: HTMLElement, result: AnalysisResult, note?: string): void {
  container.replaceChildren();

  const head = el('section', { class: 'panel result-head' }, [scoreGauge(result)]);
  if (note) head.appendChild(el('p', { class: 'teaching-note', text: note }));
  container.appendChild(head);

  container.appendChild(el('section', { class: 'panel' }, [
    el('h3', { text: 'How the score was reached' }),
    el('p', { class: 'muted', text: 'Categories are capped, so one noisy signal cannot dominate. The total below reconciles exactly to the score.' }),
    breakdownTable(result)
  ]));

  container.appendChild(findingsSection(result));
  container.appendChild(coveragePanel(result));

  container.appendChild(el('section', { class: 'panel' }, [
    el('h3', { text: 'Detail' }),
    tabs([
      { id: 'source', label: 'Annotated source', node: annotatedSource(result) },
      { id: 'headers', label: 'Headers', node: headerView(result) },
      { id: 'urls', label: 'Links', node: urlView(result) },
      { id: 'iocs', label: 'IOCs', node: iocPanel(result) }
    ])
  ]));
}



