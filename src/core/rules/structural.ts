// Structural rules that read the parse output (attachments, HTML signals,
// evasion) rather than the phrase text. Kept together because they share the
// same "read metadata, emit structuralFinding" shape.

import { structuralFinding } from '../finding';
import type { HtmlAnalysis } from '../extract/html';
import type { AttachmentInfo, Finding, NormalisedText } from '../types';

const EXECUTABLE_EXTENSIONS = ['exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'msi', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'ps1', 'hta', 'jar', 'lnk', 'cpl', 'reg', 'regsvr32', 'dll'];
const MACRO_EXTENSIONS = ['docm', 'xlsm', 'pptm', 'xlam', 'dotm'];
const ARCHIVE_EXTENSIONS = ['zip', 'rar', '7z', 'gz', 'tar', 'cab', 'ace', 'one'];
const DISK_EXTENSIONS = ['iso', 'img', 'vhd', 'vhdx'];
const HTML_EXTENSIONS = ['html', 'htm', 'xhtml', 'svg'];
const GENERIC_NAME_RE = /^(?:invoice|scan|payment|remittance|document|order|receipt|statement|attachment|file|photo)[\s_\-.]?\d+/i;

const BIDI_RE = /[\u202A-\u202E\u2066-\u2069]/;

/** Split a filename into a list of extensions (e.g. invoice.pdf.exe). */
function extensionsOf(filename: string): string[] {
  return filename.toLowerCase().split('.').slice(1);
}

function findRuleForFilename(filename: string): string | null {
  const exts = extensionsOf(filename);
  if (exts.length === 0) return null;
  const last = exts[exts.length - 1]!;
  const before = exts.length >= 2 ? exts[exts.length - 2] : null;

  if (BIDI_RE.test(filename)) return 'ATT-RTLO';
  if (before && MACRO_EXTENSIONS.includes(before) && EXECUTABLE_EXTENSIONS.includes(last)) return 'ATT-DOUBLE-EXTENSION';
  if (before && HTML_EXTENSIONS.includes(before) && EXECUTABLE_EXTENSIONS.includes(last)) return 'ATT-DOUBLE-EXTENSION';
  if (exts.length >= 2 && EXECUTABLE_EXTENSIONS.includes(last) && !EXECUTABLE_EXTENSIONS.includes(before ?? '')) {
    return 'ATT-DOUBLE-EXTENSION';
  }
  if (EXECUTABLE_EXTENSIONS.includes(last)) return 'ATT-EXECUTABLE';
  if (MACRO_EXTENSIONS.includes(last)) return 'ATT-MACRO-FILE';
  if (DISK_EXTENSIONS.includes(last)) return 'ATT-DISK-IMAGE';
  if (HTML_EXTENSIONS.includes(last)) return 'ATT-HTML-SMUGGLING';
  if (ARCHIVE_EXTENSIONS.includes(last)) return 'ATT-ARCHIVE';
  if (GENERIC_NAME_RE.test(filename)) return 'ATT-GENERIC-NAME';
  return null;
}

/** Attachment rules from the declared filename / content-type only. */
export function runAttachmentRules(attachments: AttachmentInfo[]): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const att of attachments) {
    const label = att.filename ?? att.contentType ?? 'attachment';
    if (att.filename) {
      const ruleId = findRuleForFilename(att.filename);
      if (ruleId && !seen.has(ruleId)) {
        seen.add(ruleId);
        findings.push(structuralFinding(ruleId, [{ source: 'attachment', snippet: att.filename, label: att.contentType ?? '' }]));
      }
    } else if (att.contentType?.startsWith('text/html') && !seen.has('ATT-HTML-SMUGGLING')) {
      seen.add('ATT-HTML-SMUGGLING');
      findings.push(structuralFinding('ATT-HTML-SMUGGLING', [{ source: 'attachment', snippet: label, label: 'text/html' }]));
    }
  }
  return findings;
}

/**
 * Evasion rules that need the normalised text (invisible characters) and the
 * HTML analysis (hidden text, tracking pixels).
 */
export function runTechniqueRules(
  normalised: NormalisedText,
  html: HtmlAnalysis | null,
  hasQuotedHistory: boolean,
  subject: string | null
): Finding[] {
  const findings: Finding[] = [];

  if (normalised.zeroWidthCount >= 5) {
    findings.push(structuralFinding('EVADE-ZEROWIDTH', [
      { source: 'body', snippet: `${normalised.zeroWidthCount} invisible characters removed` }
    ]));
  }

  if (normalised.homoglyphFolded) {
    findings.push(structuralFinding('EVADE-HOMOGLYPH-TEXT', [
      { source: 'body', snippet: 'Word characters folded from another alphabet' }
    ]));
  }

  if (html) {
    if (html.hiddenText.length > 20) {
      findings.push(structuralFinding('TECH-HIDDEN-TEXT', [
        { source: 'body', snippet: html.hiddenText.slice(0, 120) }
      ]));
    }
    const pixel = html.images.find((img) => img.width === 1 && img.height === 1);
    if (pixel) {
      findings.push(structuralFinding('TECH-TRACKING-PIXEL', [
        { source: 'body', snippet: pixel.src, label: '1x1 image' }
      ]));
    }
  }

  if (subject && /^(?:re|fwd|fw|aw)\s*:/.test(subject) && !hasQuotedHistory) {
    findings.push(structuralFinding('TECH-THREAD-HIJACK-LIKE', [
      { source: 'header', snippet: subject, label: 'Subject' }
    ]));
  }

  return findings;
}