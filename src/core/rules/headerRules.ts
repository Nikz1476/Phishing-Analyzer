// Header rules (HDR-*). All of these read the parsed headers, the reported
// authentication results and the LOCALLY recomputed alignment.

import { structuralFinding } from '../finding';
import { freemailDomains, brands } from '../data';
import { damerauLevenshtein } from '../url/features';
import { registrableDomain } from '../url/parse';
import { headerValues, parseAddressList, domainOf, decodeEncodedWords } from '../parse/headers';
import { computeAlignment, collectAuthResults } from '../parse/auth';
import type { AlignmentSummary, AuthResultSummary, Finding, Header, ReceivedHop } from '../types';

const EXEC_NAMES = ['ceo', 'cfo', 'cto', 'director', 'managing director', 'manager', 'finance', 'accounts', 'president', 'head', 'chairman', 'proprietor', 'founder', 'system administrator', 'it support', 'helpdesk', 'support team', 'security team', 'human resources', 'hr'];

function evidence(value: string, label: string) {
  return [{ source: 'header' as const, snippet: value.slice(0, 200), label }];
}

export interface HeaderRuleContext {
  headers: Header[];
  receivedHops: ReceivedHop[];
}

export function runHeaderRules(ctx: HeaderRuleContext): Finding[] {
  const { headers, receivedHops } = ctx;
  const findings: Finding[] = [];
  const has = (n: string) => headerValues(headers, n);

  const fromValues = has('From');
  const fromHeader = fromValues[0] ?? null;
  const fromParsed = fromHeader ? parseAddressList(fromHeader)[0] : null;
  const fromAddress = fromParsed?.address ?? null;
  const fromDisplayName = decodeEncodedWords(fromParsed?.name ?? '');
  const fromDomain = domainOf(fromAddress);
  const fromRegistrable = fromDomain ? registrableDomain(fromDomain) : null;

  const replyToHeader = has('Reply-To')[0] ?? null;
  const replyToAddress = replyToHeader ? parseAddressList(replyToHeader)[0]?.address ?? null : null;
  const returnPathHeader = has('Return-Path')[0] ?? null;
  const returnPathAddress = returnPathHeader ? parseAddressList(returnPathHeader)[0]?.address ?? null : null;
  const messageId = has('Message-ID')[0] ?? null;

  // --- multiple From headers ----------------------------------------------
  if (fromValues.length > 1) {
    findings.push(structuralFinding('HDR-MULTI-FROM', evidence(fromValues.join(' | '), 'From (x' + fromValues.length + ')')));
  }

  // --- authentication results ---------------------------------------------
  const arHeaderValues = has('Authentication-Results');
  const receivedSpfValues = has('Received-SPF');
  const authResults = collectAuthResults(arHeaderValues);
  const trusted = authResults.filter((a) => a.trusted);
  const alignment = computeAlignment(authResults, fromAddress, fromDomain);

  const spf = trusted.find((a) => a.method === 'spf');
  const dkim = trusted.find((a) => a.method === 'dkim');
  const dmarc = trusted.find((a) => a.method === 'dmarc');

  if (spf) {
    if (spf.result === 'fail') findings.push(structuralFinding('HDR-SPF-FAIL', evidence(spf.authservId, 'spf=fail')));
    else if (spf.result === 'softfail') findings.push(structuralFinding('HDR-SPF-SOFTFAIL', evidence(spf.authservId, 'spf=softfail')));
    else if (spf.result === 'permerror') findings.push(structuralFinding('HDR-SPF-PERMERROR', evidence(spf.authservId, 'spf=permerror')));
  }
  if (dkim?.result === 'fail') findings.push(structuralFinding('HDR-DKIM-FAIL', evidence(dkim.authservId, 'dkim=fail')));
  if (dmarc?.result === 'fail') findings.push(structuralFinding('HDR-DMARC-FAIL', evidence(dmarc.authservId, 'dmarc=fail')));

  // Reported pass but nothing aligns locally -> the classic forged case.
  const reportedPass = spf?.result === 'pass' || dkim?.result === 'pass' || dmarc?.result === 'pass';
  const nothingAligns = alignment && alignment.dmarc.locallyComputed === false;
  if (reportedPass && nothingAligns) {
    findings.push(structuralFinding('HDR-AUTH-MISALIGNED', evidence(
      `reported: spf=${alignment!.spf.reported} dkim=${alignment!.dkim.reported} dmarc=${alignment!.dmarc.reported}; locally aligned: none`,
      'alignment'
    )));
  }

  // Conflicting A-R headers (different authserv-ids that disagree).
  const authservIds = [...new Set(authResults.map((a) => a.authservId).filter(Boolean))];
  if (authservIds.length > 1) {
    findings.push(structuralFinding('HDR-AUTH-FORGED', evidence(authservIds.join(' vs '), 'authserv-ids')));
  }

  // No A-R and no Received-SPF: coverage gap, not a failure.
  if (arHeaderValues.length === 0 && receivedSpfValues.length === 0) {
    findings.push(structuralFinding('HDR-AUTH-ABSENT', evidence('no Authentication-Results or Received-SPF header', 'coverage')));
  }

  // --- Reply-To: mutually exclusive (mismatch / freemail / lookalike) -----
  if (replyToAddress && fromAddress && fromRegistrable) {
    const replyDomain = domainOf(replyToAddress);
    const replyRegistrable = replyDomain ? registrableDomain(replyDomain) : null;
    const isFreemail = freemailDomains.some((f) => replyDomain === f || replyDomain?.endsWith('.' + f));
    const distance = replyRegistrable ? damerauLevenshtein(replyRegistrable, fromRegistrable) : 99;

    if (replyRegistrable && distance <= 2) {
      findings.push(structuralFinding('HDR-REPLYTO-LOOKALIKE', evidence(replyToAddress, 'Reply-To ~ From domain')));
    } else if (isFreemail) {
      findings.push(structuralFinding('HDR-REPLYTO-FREEMAIL', evidence(replyToAddress, 'Reply-To is freemail')));
    } else if (replyRegistrable !== fromRegistrable) {
      findings.push(structuralFinding('HDR-REPLYTO-MISMATCH', evidence(replyToAddress, 'Reply-To domain differs')));
    }
  }

  // --- display-name spoof --------------------------------------------------
  if (fromDisplayName) {
    const nameLooksAddressish = /@/.test(fromDisplayName) &&
      (() => {
        const m = /@([\w.-]+)\.\w{2,}/.exec(fromDisplayName);
        if (!m) return false;
        const nameDomain = registrableDomain(m[1]!.toLowerCase());
        return nameDomain !== null && nameDomain !== fromRegistrable;
      })();
    const nameLower = fromDisplayName.toLowerCase();
    const nameLooksExec = EXEC_NAMES.some((n) => nameLower.includes(n)) ||
      Object.values(brands).some((b) => b.aliases.some((a) => nameLower === a.toLowerCase()));
    const fromIsFreemail = freemailDomains.some((f) => fromDomain === f || fromDomain?.endsWith('.' + f));

    if (nameLooksAddressish || (nameLooksExec && fromIsFreemail)) {
      findings.push(structuralFinding('HDR-DISPLAY-SPOOF', evidence(
        `${fromDisplayName} <${fromAddress ?? 'unknown'}>`,
        'display name vs address'
      )));
    }
  }

  // --- Return-Path vs From -------------------------------------------------
  if (returnPathAddress && fromAddress && fromDomain) {
    const rpDomain = domainOf(returnPathAddress);
    const rpReg = rpDomain ? registrableDomain(rpDomain) : null;
    if (rpReg && rpReg !== fromRegistrable) {
      const dkimAlignedPass = dkim?.result === 'pass' && alignment?.dkim.locallyAligned === true;
      // Contextual: halved when DKIM passes and is aligned (bulk senders).
      const f = structuralFinding('HDR-RETURNPATH-MISMATCH', evidence(returnPathAddress, 'Return-Path differs'),
        dkimAlignedPass ? 3 : 6);
      findings.push(f);
    }
  }

  // --- Message-ID domain ---------------------------------------------------
  if (messageId) {
    const m = /@([\w.-]+)/.exec(messageId);
    if (m && fromRegistrable) {
      const msgReg = registrableDomain(m[1]!.toLowerCase());
      if (msgReg && msgReg !== fromRegistrable && damerauLevenshtein(msgReg, fromRegistrable) > 3) {
        findings.push(structuralFinding('HDR-MSGID-MISMATCH', evidence(messageId, 'Message-ID domain differs')));
      }
    }
  }

  // --- Received-chain anomalies -------------------------------------------
  const hopNotes = receivedHops.flatMap((h) => h.notes);
  if (hopNotes.length > 0) {
    findings.push(structuralFinding('HDR-RECEIVED-ANOMALY', hopNotes.flatMap((n) => evidence(n, 'Received'))));
  }

  // --- Date anomaly --------------------------------------------------------
  const dateHeader = has('Date')[0] ?? null;
  if (dateHeader) {
    const ts = Date.parse(dateHeader);
    if (Number.isFinite(ts)) {
      const now = Date.now();
      const years = 1000 * 60 * 60 * 24 * 365;
      if (ts > now + years || ts < now - 5 * years) {
        findings.push(structuralFinding('HDR-DATE-ANOMALY', evidence(dateHeader, 'Date')));
      }
    }
  }

  return findings;
}

/** Build the alignment summary for display (re-exported for the report). */
export function alignmentFor(headers: Header[], fromAddress: string | null, fromDomain: string | null): AlignmentSummary | null {
  const arValues = headerValues(headers, 'Authentication-Results');
  const auth: AuthResultSummary[] = collectAuthResults(arValues);
  return computeAlignment(auth, fromAddress, fromDomain);
}
