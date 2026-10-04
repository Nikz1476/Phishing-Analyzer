// App shell. All state lives in memory only - no localStorage/sessionStorage/
// IndexedDB/cookies ever hold email content (Section 3), and nothing is put in
// the URL. "Clear" resets both the DOM and the in-memory variables.

import { analyse } from '../core/engine';
import { defang } from '../core/url/defang';
import { renderResult, safetyBanner, el } from './render';
import { renderLearn } from './learn';
import { SAMPLES } from './samples';
import type { AnalysisResult } from '../core/types';

const MAX_BYTES = 5 * 1024 * 1024;

type View = 'analyse' | 'learn';

// In-memory only. This is what "Clear" wipes.
let lastResult: AnalysisResult | null = null;
let lastSampleNote: string | null = null;
let sampleIndex = 0;

function $(sel: string): HTMLElement | null {
  return document.querySelector<HTMLElement>(sel);
}

function setView(view: View): void {
  const analyseView = $('#view-analyse');
  const learnView = $('#view-learn');
  if (!analyseView || !learnView) return;
  analyseView.hidden = view !== 'analyse';
  learnView.hidden = view !== 'learn';
  document.querySelectorAll<HTMLButtonElement>('.nav-btn').forEach((b) => {
    const isActive = b.dataset.view === view;
    b.classList.toggle('active', isActive);
    b.setAttribute('aria-current', isActive ? 'page' : 'false');
  });
  if (view === 'learn') renderLearn($('#learn-body')!);
}

function announce(message: string): void {
  const region = $('#live-region');
  if (region) region.textContent = message;
}

function showError(message: string): void {
  const box = $('#errors');
  if (!box) return;
  box.replaceChildren(el('p', { class: 'error', text: message }));
  announce(message);
}

function clearErrors(): void {
  $('#errors')?.replaceChildren();
}

function runAnalysis(raw: string, note: string | null): void {
  const input = raw.trim();
  if (!input) {
    showError('Paste a message (or load a sample) first.');
    return;
  }
  if (input.length > MAX_BYTES) {
    showError('That input is larger than 5 MB. Trim it and try again.');
    return;
  }

  let result: AnalysisResult;
  try {
    result = analyse(input);
  } catch (err) {
    // The engine is written never to throw; a friendly message still beats a
    // blank page if that guarantee is ever broken.
    showError(`Something went wrong reading that input: ${(err as Error).message}`);
    return;
  }

  lastResult = result;
  lastSampleNote = note;

  const out = $('#result');
  if (!out) return;
  out.hidden = false;
  renderResult(out, result, note ?? undefined);

  announce(
    `Analysis complete. Score ${result.score} out of 100, ${result.classification}. ` +
    `${result.findings.length} warning signs found.`
  );
}

function textReport(result: AnalysisResult, note: string | null): string {
  const lines: string[] = [];
  lines.push('Phishing Email Analyser - report');
  lines.push(`Score: ${result.score}/100  (${result.classification})`);
  lines.push(`Coverage: level ${result.coverage.level} of 4`);
  lines.push('');
  lines.push('Warning signs:');
  for (const f of [...result.findings].sort((a, b) => b.weight - a.weight)) {
    lines.push(`  ${f.weight} pts  ${f.id}  ${f.title}`);
    for (const e of f.evidence.slice(0, 3)) lines.push(`      evidence: ${defang(e.snippet)}`);
  }
  lines.push('');
  lines.push('Not checked:');
  for (const c of result.coverage.notChecked) lines.push(`  - ${c}`);
  if (note) lines.push('', note);
  lines.push('', 'This is an educational triage tool. It cannot determine whether an email is malicious or safe.');
  return lines.join('\n');
}

function wipeEverything(): void {
  lastResult = null;
  lastSampleNote = null;
  const textarea = $('#input') as HTMLTextAreaElement | null;
  if (textarea) textarea.value = '';
  const result = $('#result');
  if (result) { result.replaceChildren(); result.hidden = true; }
  clearErrors();
  announce('Cleared. Input, results and in-memory state have been wiped.');
}

function handleFile(file: File): void {
  if (file.size > MAX_BYTES) {
    showError('That file is larger than 5 MB.');
    return;
  }
  const reader = new FileReader();
  reader.onload = () => {
    const textarea = $('#input') as HTMLTextAreaElement | null;
    if (textarea) textarea.value = String(reader.result ?? '');
    clearErrors();
    runAnalysis(textarea?.value ?? '', null);
  };
  reader.onerror = () => showError('Could not read that file locally.');
  // readAsText is a local operation only; nothing is uploaded.
  reader.readAsText(file);
}

function init(): void {
  const app = $('#app');
  if (!app) return;

  // --- static shell ---------------------------------------------------------
  const header = el('header', { class: 'app-header' }, [
    el('h1', { text: 'Phishing Email Analyser' }),
    el('p', {
      class: 'tagline',
      text: 'Paste a suspicious email. Get a 0–100 risk score with every contributing warning sign explained.'
    })
  ]);

  const nav = el('nav', { class: 'app-nav', 'aria-label': 'Sections' }, [
    el('button', { type: 'button', class: 'nav-btn active', 'data-view': 'analyse', 'aria-current': 'page', text: 'Analyse' }),
    el('button', { type: 'button', class: 'nav-btn', 'data-view': 'learn', text: 'Learn' })
  ]);

  const liveRegion = el('div', {
    id: 'live-region', class: 'sr-only', role: 'status', 'aria-live': 'polite'
  });

  // --- input ---------------------------------------------------------------
  const input = el('textarea', {
    id: 'input',
    rows: '14',
    spellcheck: 'false',
    placeholder: 'Paste the full message here (headers + body if you have them), or drop a .eml file below.'
  }) as HTMLTextAreaElement;

  const analyseBtn = el('button', { id: 'analyse-btn', type: 'button', class: 'btn primary', text: 'Analyse Email' });
  const sampleBtn = el('button', { id: 'sample-btn', type: 'button', class: 'btn', text: 'Load sample' });
  const clearBtn = el('button', { id: 'clear-btn', type: 'button', class: 'btn', text: 'Clear' });
  const copyBtn = el('button', { id: 'copy-btn', type: 'button', class: 'btn', text: 'Copy report' });
  copyBtn.disabled = true;

  const buttons = el('div', { class: 'actions' });
  buttons.append(analyseBtn, sampleBtn, clearBtn, copyBtn);

  const fileInput = el('input', { type: 'file', id: 'file-input', accept: '.eml,.txt' }) as HTMLInputElement;
  const fileLabel = el('label', { class: 'file-label', text: 'or drop a .eml file: ' });
  fileLabel.appendChild(fileInput);

  const dropZone = el('section', { class: 'panel input-panel' }, [
    el('h2', { text: '1. Paste the message' }),
    input,
    buttons,
    fileLabel,
    el('div', { id: 'errors' }),
    el('p', {
      class: 'muted',
      text: 'Nothing you paste is uploaded or stored. Analysis runs entirely in this browser tab.'
    })
  ]);

  const resultPanel = el('section', { id: 'result', class: 'results', hidden: true });

  const analyseView = el('div', { id: 'view-analyse' }, [safetyBanner(), dropZone, resultPanel]);
  const learnView = el('div', { id: 'view-learn', hidden: true }, [el('div', { id: 'learn-body' })]);

  app.replaceChildren(header, nav, liveRegion, analyseView, learnView);

  // --- wiring ---------------------------------------------------------------
  nav.querySelectorAll<HTMLButtonElement>('.nav-btn').forEach((b) => {
    b.addEventListener('click', () => setView(b.dataset.view as View));
  });

  analyseBtn.addEventListener('click', () => {
    clearErrors();
    runAnalysis(input.value, null);
    copyBtn.disabled = lastResult === null;
  });

  sampleBtn.addEventListener('click', () => {
    const sample = SAMPLES[sampleIndex % SAMPLES.length];
    sampleIndex += 1;
    if (!sample) return;
    input.value = sample.raw;
    clearErrors();
    runAnalysis(sample.raw, sample.note);
    copyBtn.disabled = lastResult === null;
  });

  clearBtn.addEventListener('click', wipeEverything);

  copyBtn.addEventListener('click', async () => {
    if (!lastResult) return;
    await navigator.clipboard.writeText(textReport(lastResult, lastSampleNote));
    copyBtn.textContent = 'Copied';
    setTimeout(() => { copyBtn.textContent = 'Copy report'; }, 1200);
  });

  fileInput.addEventListener('change', () => {
    const file = fileInput.files?.[0];
    if (file) handleFile(file);
  });

  // Drag-and-drop is a local file read only.
  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragging');
  });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragging'));
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragging');
    const file = e.dataTransfer?.files?.[0];
    if (file) handleFile(file);
  });
}

init();


