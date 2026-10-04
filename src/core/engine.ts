// The pipeline. Each stage is a pure function; this file only wires them in
// the order specified in Section 4. It is the ONLY place that knows the order,
// so the individual stages stay independently testable.

import { brands, weights } from './data';
import { parseMessage } from './parse/message';
import { headerValues, parseAddressList, domainOf, decodeEncodedWords } from './parse/headers';
import { collectAuthResults, computeAlignment, parseReceivedChain } from './parse/auth';
import { normalise } from './normalise/text';
import { analyseHtml, type HtmlAnalysis } from './extract/html';
import { extractUrlsFromText, mergeExtractedUrls, dedupeUrls } from './extract/urls';
import { extractEmails, extractIps, hasCryptoAddress } from './extract/iocs';
import { analyseUrl } from './url/analyse';
import { registrableDomain } from './url/parse';
import { runPhraseRules, type RuleContext } from './rules/phraseEngine';
import { runAttachmentRules, runTechniqueRules } from './rules/structural';
import { runHeaderRules } from './rules/headerRules';
import { structuralFinding } from './finding';
import { score } from './score/score';
import type {
  AnalysisResult, AttachmentInfo, Coverage, Finding, HeaderReport, Iocs, Mitigation,
  ParsedMessage, UrlReport
} from './types';

export interface AnalyseOptions {
  /** Recipient addresses (To/Cc) used by the personalised-URL rule. */
  recipients?: string[];
}

function firstHeader(msg: ParsedMessage, name: string): string | null {
  const v = headerValues(msg.headers, name);
  return v.length > 0 ? v[0]! : null;
}

function recipientsOf(msg: ParsedMessage): string[] {
  const out: string[] = [];
  for (const name of ['To', 'Cc', 'Delivered-To', 'X-Original-To']) {
    for (const value of headerValues(msg.headers, name)) {
      for (const addr of parseAddressList(value)) {
        if (addr.address) out.push(addr.address);
      }
    }
  }
  return [...new Set(out)];
}

/** Which brands does the message claim to be talking about? */
function claimedBrands(text: string, subject: string, displayName: string | null): string[] {
  const haystack = `${text} ${subject} ${displayName ?? ''}`.toLowerCase();
  const claimed: string[] = [];
  for (const [key, entry] of Object.entries(brands)) {
    const hit = entry.aliases.some((a) => haystack.includes(a.toLowerCase()));
    if (hit) claimed.push(key);
  }
  return claimed;
}

function buildCoverage(msg: ParsedMessage, alignmentAvailable: boolean): Coverage {
  const level: 1 | 2 | 3 | 4 = msg.isRaw
    ? alignmentAvailable ? 4 : headerValues(msg.headers, 'From').length > 0 ? 3 : 2
    : 1;
  const checked: string[] = [];
  const notChecked: string[] = [];

  checked.push('Message text (phrasing, commands, requests)');
  notChecked.push('Link destinations: never visited (no network access)');

  if (level >= 2) {
    checked.push('Sender identity headers (From, Reply-To, Return-Path, Message-ID)');
  } else {
    notChecked.push('Sender identity headers: none supplied');
  }

  if (level >= 3 || alignmentAvailable) {
    checked.push('Receiving-server authentication results (as reported)');
    if (!alignmentAvailable) notChecked.push('Alignment recomputation: no Authentication-Results properties to compare');
  } else {
    notChecked.push('SPF/DKIM/DMARC: not available');
  }

  if (level >= 4) {
    checked.push('Raw MIME structure and attachment names');
    notChecked.push('Attachment contents: never inspected');
  } else {
    notChecked.push('Attachment list: only supplied as text');
  }

  if (msg.bodyHtml === null) notChecked.push('HTML-only content: none supplied');
  if (!/[\p{L}]/u.test(msg.bodyText)) notChecked.push('Image-only content: no readable text');

  return { level, checked, notChecked };
}

function buildHeaderReport(msg: ParsedMessage): HeaderReport | null {
  if (!msg.isRaw || msg.headers.length === 0) return null;
  const fromHeader = firstHeader(msg, 'From');
  const fromParsed = fromHeader ? parseAddressList(fromHeader)[0] : null;
  const fromAddress = fromParsed?.address ?? null;
  const fromDomain = domainOf(fromAddress);

  const arValues = headerValues(msg.headers, 'Authentication-Results');
  const authResults = collectAuthResults(arValues);
  const receivedHops = parseReceivedChain(headerValues(msg.headers, 'Received'));
  const alignment = computeAlignment(authResults, fromAddress, fromDomain);

  const replyTo = firstHeader(msg, 'Reply-To');
  const returnPath = firstHeader(msg, 'Return-Path');

  return {
    from: fromAddress,
    replyTo: replyTo ? parseAddressList(replyTo)[0]?.address ?? replyTo : null,
    returnPath: returnPath ? parseAddressList(returnPath)[0]?.address ?? returnPath : null,
    messageId: firstHeader(msg, 'Message-ID'),
    subject: firstHeader(msg, 'Subject') ? decodeEncodedWords(firstHeader(msg, 'Subject')!) : null,
    date: firstHeader(msg, 'Date'),
    authResults,
    receivedHops,
    alignment
  };
}

function buildIocs(text: string, urlReports: UrlReport[], msg: ParsedMessage): Iocs {
  const emails = new Set<string>(extractEmails(text));
  const urls = new Set<string>();
  const domains = new Set<string>();
  const ips = new Set<string>(extractIps(text));

  for (const r of urlReports) {
    urls.add(r.defanged);
    if (r.registrableDomain) domains.add(r.registrableDomain + '.');
  }
  for (const e of extractEmails(text)) emails.add(e);
  for (const a of parseAddressList(firstHeader(msg, 'From') ?? '')) {
    if (a.address) emails.add(a.address);
  }

  return {
    urls: [...urls].sort(),
    domains: [...domains].sort(),
    ips: [...ips].sort(),
    emails: [...emails].sort(),
    hashes: [] // hashing the whole message is not meaningful without attachments
  };
}

/**
 * Mitigations (Section 9.3). Deliberately small, and NEVER applied when a
 * critical finding exists - score() enforces that second part.
 */
function buildMitigations(
  authResults: ReturnType<typeof collectAuthResults>,
  alignment: ReturnType<typeof computeAlignment>,
  urlReports: UrlReport[],
  fromDomain: string | null
): Mitigation[] {
  const out: Mitigation[] = [];
  const trusted = authResults.filter((a) => a.trusted);
  const spfPass = trusted.find((a) => a.method === 'spf')?.result === 'pass';
  const dkimPass = trusted.find((a) => a.method === 'dkim')?.result === 'pass';
  const dmarcPass = trusted.find((a) => a.method === 'dmarc')?.result === 'pass';
  const aligned =
    alignment?.spf.locallyAligned === true &&
    alignment?.dkim.locallyAligned === true &&
    alignment?.dmarc.locallyComputed === true;

  if (spfPass && dkimPass && dmarcPass && aligned) {
    out.push({
      id: 'MIT-AUTH-ALIGNED',
      delta: weights.mitigations['MIT-AUTH-ALIGNED'] ?? -8,
      because: 'SPF, DKIM and DMARC all pass and align with the From domain.'
    });
  }

  const fromReg = fromDomain ? registrableDomain(fromDomain) : null;
  if (urlReports.length > 0 && fromReg) {
    const allSame = urlReports.every((r) => r.registrableDomain === fromReg);
    if (allSame) {
      out.push({
        id: 'MIT-LINKS-SAME-DOMAIN',
        delta: weights.mitigations['MIT-LINKS-SAME-DOMAIN'] ?? -5,
        because: 'Every link resolves to the authenticated From domain.'
      });
    }
  }
  return out;
}

/** Run the full pipeline over pasted input. */
export function analyse(rawInput: string, options: AnalyseOptions = {}): AnalysisResult {
  const msg = parseMessage(rawInput);
  const subject = msg.isRaw ? decodeEncodedWords(firstHeader(msg, 'Subject') ?? '') : '';

  // ---- normalise -----------------------------------------------------------
  const normalised = normalise(msg.bodyText);

  // ---- HTML ---------------------------------------------------------------
  let html: HtmlAnalysis | null = null;
  if (msg.bodyHtml) {
    try {
      html = analyseHtml(msg.bodyHtml);
    } catch {
      html = null; // malformed HTML must never abort analysis
    }
  }
  const htmlHiddenText = html?.hiddenText ? `\n${html.hiddenText}` : '';
  const analysable = normalise(`${normalised.text}\n${subject}\n${htmlHiddenText}`);
  const matchCombined = analysable.text;

  // ---- extract -------------------------------------------------------------
  const textUrls = extractUrlsFromText(msg.bodyText);
  const anchors = html?.anchors ?? [];
  const urls = dedupeUrls(mergeExtractedUrls(anchors, textUrls));
  const recipients = (options.recipients ?? []).concat(recipientsOf(msg));

  // ---- URL analysis --------------------------------------------------------
  const urlReports: UrlReport[] = urls.map((u) => analyseUrl(u, recipients));
  urlReports.forEach((r, i) => {
    for (const f of r.findings) f.groupId = `url-${i}`;
  });

  // ---- context flags -------------------------------------------------------
  const attachments: AttachmentInfo[] = msg.attachments;
  const flags = new Set<string>();
  if (urls.length > 0) flags.add('has-url');
  if (attachments.length > 0) flags.add('has-attachment');
  if (html?.hasPasswordField) { flags.add('has-password-form'); flags.add('has-html-form'); }
  if (hasCryptoAddress(matchCombined)) flags.add('has-crypto-address');

  const context: RuleContext = { flags };

  // ---- rules ---------------------------------------------------------------
  const findings: Finding[] = [];
  const fromHeader = firstHeader(msg, 'From');
  const fromAddress = fromHeader ? parseAddressList(fromHeader)[0]?.address ?? null : null;
  const fromDomain = domainOf(fromAddress);
  const displayName = fromHeader ? decodeEncodedWords(parseAddressList(fromHeader)[0]?.name ?? '') : null;

  findings.push(...runPhraseRules(analysable, context));
  findings.push(...runAttachmentRules(attachments));

  const hasQuotedHistory = /^>+.*\|/m.test(msg.bodyText) || /\bwrote:/.test(msg.bodyText);
  findings.push(...runTechniqueRules(normalised, html, hasQuotedHistory, subject));

  if (msg.isRaw && msg.headers.length > 0) {
    findings.push(...runHeaderRules({
      headers: msg.headers,
      receivedHops: buildHeaderReport(msg)?.receivedHops ?? []
    }));
  } else {
    findings.push(structuralFinding('HDR-AUTH-ABSENT', [
      { source: 'header', snippet: 'No raw headers were supplied', label: 'coverage' }
    ], 0));
  }

  if (html?.hasPasswordField) {
    const action = html.forms.find((f) => f.hasPassword)?.action ?? '';
    findings.push(structuralFinding('CRED-HTML-FORM', [
      { source: 'body', snippet: action ? `form action: ${action}` : 'password field', label: 'HTML' }
    ]));
  }

  // ---- brand impersonation --------------------------------------------------
  const claimed = claimedBrands(matchCombined, subject, displayName);
  const headerReport = buildHeaderReport(msg);
  const dkimDomains = (headerReport?.authResults ?? [])
    .filter((a) => a.method === 'dkim')
    .map((a) => a.properties['header.d'])
    .filter((v): v is string => !!v);
  const infraDomains = new Set<string>();
  if (fromDomain) { const r = registrableDomain(fromDomain); if (r) infraDomains.add(r); }
  for (const r of urlReports) if (r.registrableDomain) infraDomains.add(r.registrableDomain);
  for (const d of dkimDomains) { const r = registrableDomain(d); if (r) infraDomains.add(r); }

  for (const brandKey of claimed) {
    const entry = brands[brandKey];
    if (!entry) continue;
    const legitPresent = entry.legitDomains.some((d) => infraDomains.has(d));
    if (!legitPresent) {
      findings.push(structuralFinding('IMP-BRAND-MISMATCH', [
        {
          source: 'body',
          snippet: `Message refers to "${entry.aliases[0]}" but no known ${brandKey} domain appears in the sender, links or DKIM.`,
          label: brandKey
        }
      ]));
      break; // one finding is enough; multiple brands are usually one narrative
    }
  }

  // ---- platform abuse gating ------------------------------------------------
  const hasCredentialOrImpersonation = findings.some(
    (f) => f.category === 'credential' || f.category === 'impersonation'
  );
  const filteredFindings = hasCredentialOrImpersonation
    ? findings
    : findings.filter((f) => f.id !== 'URL-PLATFORM-ABUSE');
  if (!hasCredentialOrImpersonation) {
    for (const r of urlReports) {
      r.findings = r.findings.filter((f) => f.id !== 'URL-PLATFORM-ABUSE');
    }
  }
  const allFindings = [...filteredFindings, ...urlReports.flatMap((r) => r.findings)];

  // ---- mitigations + score --------------------------------------------------
  const authResults = headerReport?.authResults ?? [];
  const alignment = headerReport?.alignment ?? null;
  const mitigations = buildMitigations(authResults, alignment, urlReports, fromDomain);
  const result = score({ findings: allFindings, mitigations });

  return {
    score: result.score,
    classification: result.classification,
    coverage: buildCoverage(msg, alignment !== null),
    findings: allFindings,
    breakdown: result.breakdown,
    combos: result.combos,
    mitigations: result.mitigations,
    iocs: buildIocs(matchCombined, urlReports, msg),
    original: rawInput,
    urlReports,
    headerReport,
    qrReport: null
  };
}


