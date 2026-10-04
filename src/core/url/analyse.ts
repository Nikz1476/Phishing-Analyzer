// URL analysis - fires the URL-* structural rules for a single URL.
//
// WHY the rules run against the UNWRAPPED inner URL: the wrapper is just a
// hop (a security gateway, or an attacker hiding the destination). The inner
// url is what the victim actually lands on, so that is what must be judged.

import { brands, legitDomainToBrand, platformDomains, riskyTlds, shortenerDomains } from '../data';
import { refang, defang } from './defang';
import { decodeHostname } from './punycode';
import { damerauLevenshtein, isMixedScript, shannonEntropy, skeletonFold } from './features';
import { parseUrl, registrableDomain, type UrlParts } from './parse';
import { unwrapUrl } from './unwrap';
import { structuralFinding } from '../finding';
import type { Evidence, ExtractedUrl, Finding, UrlReport } from '../types';

const COMBO_TOKENS = ['login', 'logon', 'secure', 'security', 'verify', 'verification', 'support', 'account', 'accounts', 'update', 'billing', 'helpdesk', 'portal', 'sign', 'signin', 'auth', 'session', 'client', 'validate', 'review'];

function evidence(text: string, label: string): Evidence[] {
  return [{ source: 'url', snippet: defang(text), label }];
}

/** Does a string look like a domain or full URL (used for anchor-text mismatch)? */
function looksLikeDomain(text: string): boolean {
  const t = text.trim().toLowerCase();
  if (t.includes('://')) return true;
  if (/^www\./.test(t)) return true;
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+([/?#].*)?$/i.test(t);
}

function brandLabelsList(): string[] {
  const labels = new Set<string>();
  for (const entry of Object.values(brands)) {
    for (const l of entry.labels) labels.add(l.toLowerCase());
    for (const a of entry.aliases) labels.add(a.toLowerCase().split(/\s+/)[0]!);
  }
  return [...labels];
}

function isLegitDomain(reg: string | null): boolean {
  return reg !== null && legitDomainToBrand.has(reg);
}

/** Nearest brand label within the typosquat threshold for this length. */
function typosquatMatch(label: string): string | null {
  const target = label.toLowerCase();
  if (target.length < 5) return null;
  const maxDistance = target.length >= 9 ? 2 : 1;
  for (const brandLabel of brandLabelsList()) {
    if (brandLabel.length < 3) continue;
    const d = damerauLevenshtein(target, brandLabel);
    if (d <= maxDistance && d > 0) return brandLabel;
    // Skeleton match (rn->m, 0->o, 1->l ...) counts as exact-ish.
    if (skeletonFold(target) === skeletonFold(brandLabel) && target !== brandLabel) return brandLabel;
  }
  return null;
}

function comboMatch(label: string): string | null {
  const target = label.toLowerCase();
  for (const brandLabel of brandLabelsList()) {
    if (brandLabel.length < 4) continue;
    if (target === brandLabel) continue;
    if (target.includes(brandLabel)) {
      for (const token of COMBO_TOKENS) {
        if (target.includes(token)) return `${brandLabel}-${token}`;
      }
    }
  }
  return null;
}


function base64Of(text: string): string | null {
  try {
    return btoa(text).replace(/=+$/, '');
  } catch {
    return null;
  }
}

/** Recipient's address (plain, percent-encoded or base64) in query/fragment? */
function personalised(parts: UrlParts, recipients: string[]): boolean {
  const haystack = (parts.query + parts.fragment).toLowerCase();
  if (!haystack) return false;
  for (const r of recipients) {
    const rl = r.toLowerCase();
    if (haystack.includes(rl)) return true;
    if (haystack.includes(encodeURIComponent(rl).toLowerCase())) return true;
    const b64 = base64Of(rl);
    if (b64 && haystack.includes(b64)) return true;
  }
  return false;
}

function platformAbuse(parts: UrlParts): boolean {
  const host = parts.host;
  return platformDomains.some((p) => host === p || host.endsWith(`.${p}`));
}

/** Analyse one URL and return its report plus the findings it fired. */
export function analyseUrl(entry: ExtractedUrl, recipients: string[] = []): UrlReport {
  const refanged = refang(entry.raw);
  const unwrap = unwrapUrl(refanged);
  const target = unwrap.final;
  const parts = parseUrl(target);
  const findings: Finding[] = [];
  const chainDisplay = unwrap.chain.map(defang);

  if (!parts) {
    const f = structuralFinding('URL-DATA-SCHEME', evidence(refanged, 'invalid URL'), 0);
    f.title = 'Link could not be parsed';
    f.why = 'The link is malformed, so it cannot be reliably understood. That is itself suspicious.';
    findings.push(f);
    return {
      url: entry.raw,
      defanged: defang(entry.raw),
      registrableDomain: '',
      scheme: '',
      host: '',
      unwrapChain: chainDisplay,
      findings,
      fromUnwrap: unwrap.chain.length > 1
    };
  }

  const reg = parts.registrableDomain ?? '';
  const label = reg ? reg.split('.')[0]! : '';

  const report: UrlReport = {
    url: target,
    defanged: defang(target),
    registrableDomain: reg,
    scheme: parts.scheme,
    host: parts.host,
    unwrapChain: chainDisplay,
    findings,
    fromUnwrap: unwrap.chain.length > 1
  };

  // --- non-http(s) scheme -------------------------------------------------
  if (!['http', 'https', 'ftp', 'ftps'].includes(parts.scheme)) {
    findings.push(structuralFinding('URL-DATA-SCHEME', evidence(refanged, 'scheme: ' + parts.scheme)));
    return report;
  }

  // --- redirect wrapper ---------------------------------------------------
  if (unwrap.chain.length > 1) {
    findings.push(structuralFinding('URL-WRAPPED-REDIRECT', evidence(entry.raw, 'wrapper')));
  }
  if (unwrap.loop) {
    const f = structuralFinding('URL-WRAPPED-REDIRECT', evidence(entry.raw, 'redirect loop'), 8);
    f.title = 'Redirect wrapper loops back on itself';
    findings.push(f);
  }

  // --- encoded / raw IP host ---------------------------------------------
  if (parts.encodedIp) {
    findings.push(structuralFinding('URL-IP-ENCODED', evidence(parts.rawHost, 'obfuscated host')));
  } else if (parts.isIp) {
    findings.push(structuralFinding('URL-IP-HOST', evidence(parts.host, 'IP host')));
  }

  // --- shortener -----------------------------------------------------------
  if (reg && shortenerDomains.includes(reg)) {
    findings.push(structuralFinding('URL-SHORTENER', evidence(refanged, 'shortened')));
  }

  // --- userinfo ------------------------------------------------------------
  if (parts.userinfo) {
    findings.push(structuralFinding('URL-USERINFO', evidence(parts.rawHost, 'userinfo: ' + parts.userinfo)));
  }

  // --- punycode / mixed script --------------------------------------------
  let punycodeLabel: string | null = null;
  const punyIdx = parts.labels.findIndex((l) => l.startsWith('xn--'));
  if (punyIdx >= 0) {
    const decoded = decodeHostname(parts.host);
    punycodeLabel = decoded.split('.')[punyIdx] ?? null;
    findings.push(structuralFinding('URL-PUNYCODE', evidence(parts.host, 'decoded: ' + decoded)));
  }

  const mixedScript = parts.labels.some((l) => isMixedScript(l, decodeHostname(l)));
  const brandSkeletonMatch = punycodeLabel
    ? brandLabelsList().some((b) => skeletonFold(punycodeLabel!) === skeletonFold(b))
    : false;
  if (mixedScript || brandSkeletonMatch) {
    findings.push(structuralFinding(
      'URL-MIXED-SCRIPT',
      evidence(parts.host, 'skeleton: ' + skeletonFold(punycodeLabel ?? parts.host))
    ));
  }

  // --- anchor text vs destination (URL-TEXT-MISMATCH) -----------------------
  if (entry.displayText && looksLikeDomain(entry.displayText)) {
    const displayHost = entry.displayText.trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/^www\./, '').split(/[/?#]/)[0] ?? '';
    const displayReg = registrableDomain(displayHost);
    if (displayReg && reg && displayReg !== reg && displayReg !== parts.host) {
      findings.push(structuralFinding('URL-TEXT-MISMATCH',
        evidence(entry.displayText.trim(), `text says ${displayReg}, link goes to ${reg}`)));
    }
  }

  // --- brand rules (only when the registrable domain is NOT the brand) ------
  const legit = isLegitDomain(reg);
  const regLabelCount = reg ? reg.split('.').length : 1;
  const subdomainLabels = parts.labels.slice(0, Math.max(0, parts.labels.length - regLabelCount));
  const pathAndSub = [...subdomainLabels, ...parts.path.split(/[/?=&]/).filter(Boolean)];

  if (!legit) {
    const brandInSub = pathAndSub.find((l) => {
      const lower = l.toLowerCase();
      if (brandLabelsList().includes(lower)) return true;
      return Object.values(brands).some((b) =>
        b.aliases.some((a) => a.toLowerCase() === lower)
      );
    });
    if (brandInSub) {
      findings.push(structuralFinding('URL-BRAND-IN-SUBDOMAIN', evidence(parts.host, 'label: ' + brandInSub)));
    }

    const typo = typosquatMatch(label);
    if (typo) findings.push(structuralFinding('URL-TYPOSQUAT', evidence(reg, 'similar to: ' + typo)));

    const combo = comboMatch(label);
    if (combo) findings.push(structuralFinding('URL-COMBOSQUAT', evidence(reg, 'brand + token: ' + combo)));
  }

  // --- contextual / weak signals -------------------------------------------
  if (platformAbuse(parts)) {
    findings.push(structuralFinding('URL-PLATFORM-ABUSE', evidence(parts.host, 'free platform')));
  }

  if (personalised(parts, recipients)) {
    findings.push(structuralFinding('URL-PERSONALISED', evidence(refanged, 'recipient address present')));
  }

  if (label.length >= 12 && shannonEntropy(reg) >= 3.8) {
    findings.push(structuralFinding('URL-HIGH-ENTROPY', evidence(reg, 'entropy: ' + shannonEntropy(reg).toFixed(2))));
  }

  const tld = parts.host.split('.').pop() ?? '';
  if (riskyTlds.includes(tld)) {
    findings.push(structuralFinding('URL-RISKY-TLD', evidence('.' + tld, 'risky TLD')));
  }

  if (parts.port && parts.port !== '80' && parts.port !== '443') {
    findings.push(structuralFinding('URL-NONSTANDARD-PORT', evidence(`${parts.host}:${parts.port}`, 'port ' + parts.port)));
  }

  const loginWords = ['login', 'signin', 'sign-in', 'logon', 'authenticate', 'password', 'account', 'verify', 'credential'];
  const lowerPath = (parts.path + parts.query).toLowerCase();
  if (parts.scheme === 'http' && loginWords.some((w) => lowerPath.includes(w))) {
    findings.push(structuralFinding('URL-NO-TLS-LOGIN', evidence(refanged, 'http + login wording')));
  }

  if (parts.subdomainDepth >= 4) {
    findings.push(structuralFinding('URL-DEEP-SUBDOMAIN', evidence(parts.host, 'depth ' + parts.subdomainDepth)));
  }

  return report;
}
